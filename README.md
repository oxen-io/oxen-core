# Oxen

Copyright (c) 2018-2022 The Oxen Project.   
Portions Copyright (c) 2014-2019 The Monero Project.   
Portions Copyright (c) 2012-2013 The Cryptonote developers.

## Development resources

- Web: [oxen.io](https://oxen.io)
- Telegram: [t.me/OxenCommunity](https://t.me/Oxen_Community)
- Mail: [team@oxen.io](mailto:team@oxen.io)
- GitHub: [https://github.com/oxen-io/oxen-core](https://github.com/oxen-io/oxen-core)
- Discord: [https://discord.gg/67GXfD6](https://discord.gg/67GXfD6)

## Vulnerability disclosure

- Check out our [Vulnerability Response Process](https://github.com/oxen-io/oxen-docs/blob/master/docs/Contributing/VULNERABILITY_RESPONSE_LOKI.md), encourages prompt disclosure of any Vulnerabilities

## Information

Oxen is a private cryptocurrency based on Monero. Oxen currently offers an incentivised full node layer, over the coming months we will be looking to support a secondary p2p network (Lokinet) and a messenger that offers private communications based on the Signal protocol (Session).

More information on the project can be found on the website and in the whitepaper.

Oxen is an open source project, and we encourage contributions from anyone with something to offer. For more information on contributing, please contact team@oxen.io

## Compiling Oxen from source

### Dependencies

The following table summarizes the tools and libraries required to build. A
few of the libraries are also included in this repository (marked as
"Vendored"). By default, the build uses the library installed on the system,
and ignores the vendored sources. However, if no library is found installed on
the system, then the vendored source will be built and used. The vendored
sources are also used for statically-linked builds because distribution
packages often include only shared library binaries (`.so`) but not static
library archives (`.a`).

| Dep          | Min. version  | Vendored | Debian/Ubuntu pkg      | Arch pkg     | Fedora              | Optional | Purpose          |
| ------------ | ------------- | -------- | ---------------------- | ------------ | ------------------- | -------- | ---------------- |
| GCC          | 8.1.0         | NO       | `g++`[1]               | `base-devel` | `gcc`               | NO       |                  |
| CMake        | 3.13          | NO       | `cmake`                | `cmake`      | `cmake`             | NO       |                  |
| pkg-config   | any           | NO       | `pkg-config`           | `base-devel` | `pkgconf`           | NO       |                  |
| Boost        | 1.65          | NO       | `libboost-all-dev`[2]  | `boost`      | `boost-devel`       | NO       | C++ libraries    |
| libzmq       | 4.3.0         | YES      | `libzmq3-dev`          | `zeromq`     | `zeromq-devel`      | NO       | ZeroMQ library   |
| sqlite3      | 3.24.0        | YES      | `libsqlite3-dev`       | `sqlite`     | `sqlite-devel`      | NO       | ONS, batching    |
| libsodium    | 1.0.9         | YES      | `libsodium-dev`        | `libsodium`  | `libsodium-devel`   | NO       | cryptography     |
| libcurl      | 4.0           | NO       | `libcurl4-dev`         | `curl`       | `curl-devel`        | NO       | HTTP RPC         |
| libuv (Win)  | any           | NO       | (Windows only)         | --           | --                  | NO       | RPC event loop   |
| libunwind    | any           | NO       | `libunwind8-dev`       | `libunwind`  | `libunwind-devel`   | YES      | Stack traces     |
| liblzma      | any           | NO       | `liblzma-dev`          | `xz`         | `xz-devel`          | YES      | For libunwind    |
| libreadline  | 6.3.0         | NO       | `libreadline-dev`      | `readline`   | `readline-devel`    | YES      | Input editing    |
| Doxygen      | any           | NO       | `doxygen`              | `doxygen`    | `doxygen`           | YES      | Documentation    |
| Graphviz     | any           | NO       | `graphviz`             | `graphviz`   | `graphviz`          | YES      | Documentation    |
| Qt tools     | 5.x           | NO       | `qttools5-dev`         | `qt5-tools`  | `qt5-linguist`      | YES      | Translations     |
| libhidapi    | ?             | NO       | `libhidapi-dev`        | `hidapi`     | `hidapi-devel`      | YES      | Hardware wallet  |
| libusb       | ?             | NO       | `libusb-dev`           | `libusb`     | `libusb-devel`      | YES      | Hardware wallet  |
| libprotobuf  | ?             | NO       | `libprotobuf-dev`      | `protobuf`   | `protobuf-devel`    | YES      | Hardware wallet  |
| protoc       | ?             | NO       | `protobuf-compiler`    | `protobuf`   | `protobuf-compiler` | YES      | Hardware wallet  |


[1] On Ubuntu Bionic you will need the g++-8 package instead of g++ (which is version 7) and will
need to run `export CC=gcc-8 CXX=g++-8` before running `make` or `cmake`.

[2] libboost-all-dev includes a lot of unnecessary packages; see the apt command below for a
breakdown of the minimum set of required boost packages.

Install all dependencies at once on Debian/Ubuntu:

```
sudo apt update && sudo apt install build-essential cmake pkg-config libboost-all-dev libzmq3-dev libsodium-dev libunwind8-dev liblzma-dev libreadline6-dev doxygen graphviz libpgm-dev libsqlite3-dev libcurl4-dev
```

Install all dependencies at once on macOS with the provided Brewfile:
```brew update && brew bundle --file=contrib/brew/Brewfile --no-lock```

FreeBSD one liner for required to build dependencies
```pkg install git gmake cmake pkgconf boost-libs libzmq4 libsodium sqlite3```

### Build instructions

Oxen uses the CMake build system which is used by creating a build directory and invoke cmake before building.

#### On Linux and macOS

You do not have to build from source if you are on debian or ubuntu as we have apt repositories with pre-built oxen packages on `deb.oxen.io`.

You can install these using:

	$ sudo curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg
	$ echo "deb https://deb.oxen.io $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/oxen.list
	$ sudo apt update
	$ sudo apt install oxend

if you want to build a dev build you can do the following after installing the dependancies above:

	$ git clone --recursive https://github.com/oxen-io/oxen-core.git
	$ cd oxen-core
	$ git submodule update --init --recursive
	$ mkdir build
	$ cd build
	$ cmake ..
	$ make -j$(nproc)

* The resulting executables can be found in `~/oxen-core/build/bin`

* Add `PATH="$PATH:$HOME/oxen-core/build/bin"` to `.profile`

* Run Oxen with `oxend --detach`

* **Optional**: build and run the test suite to verify the binaries:

    ```bash
    make release-test
    ```

    *NOTE*: `core_tests` test may take a few hours to complete.

* **Optional**: to build binaries suitable for debugging:

    ```bash
    make debug
    ```

* **Optional**: to build statically-linked binaries:

    ```bash
    make release-static
    ```

Dependencies need to be built with -fPIC. Static libraries usually aren't, so you may have to build them yourself with -fPIC. Refer to their documentation for how to build them.

* **Optional**: build documentation in `doc/html` (omit `HAVE_DOT=YES` if `graphviz` is not installed):

    ```bash
    HAVE_DOT=YES doxygen Doxyfile
    ```

#### On the Raspberry Pi (and similar ARM-based devices)

The build process is exactly the same, but note that some parts of the build require around 3GB of
RAM which is more memory than most Raspberry Pi class devices have available.  You can work around
this by enabling 2GB (or more) of swap, but this is not particularly recommended, particularly if
the swap file is on the SD card: intensive writes to a swap file on an SD card can accelerate how
quickly the SD card wears out.  Devices with 4GB of RAM (such as the 4GB model of the Pi 4B, and
some other SBC ARM devices) can build without needing swap.

As an alternative, pre-built oxen debs are available for ARM32 and ARM64 for recent
Debian/Raspbian/Ubuntu distributions and are often a much better alternative for SBC-class devices.
If you still want to compile from source, ensure you have enough memory (or swap -- consult your OS
documentation to learn how to enable or increase swap size) and follow the regular linux build
instructions above.

#### On Windows:

Binaries for Windows are built on Windows using the MinGW toolchain within
[MSYS2 environment](https://www.msys2.org). The MSYS2 environment emulates a
POSIX system. The toolchain runs within the environment and *cross-compiles*
binaries that can run outside of the environment as a regular Windows
application.

**Preparing the build environment**

* Download and install the [MSYS2 installer](https://www.msys2.org), either the 64-bit (x86_64) or the 32-bit (i686) package, depending on your system.
* Note: Installation must be on the C drive and root directory as result of [Monero issue 3167](https://github.com/monero-project/monero/issues/3167).
* Open the MSYS shell via the `MSYS2 MSYS` shortcut in the Start Menu or "C:\msys64\msys2_shell.cmd -msys"
* Update packages using pacman:  

    ```bash
    pacman -Syu
    ```

* Exit the MSYS shell using Alt+F4 when you get a warning stating: "terminate MSYS2 without returning to shell and check for updates again/for example close your terminal window instead of calling exit"

    ```bash
    pacman -Syu
    ```

* Update packages again using pacman: 

        pacman -Syu  

* Install dependencies:

    To build for 64-bit Windows:

    ```bash
    pacman -S git mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium mingw-w64-x86_64-hidapi mingw-w64-x86_64-sqlite3
    ```

    To build for 32-bit Windows:

    ```bash
    pacman -S git mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-zeromq mingw-w64-i686-libsodium mingw-w64-i686-hidapi mingw-w64-i686-sqlite3
    ```

* Close and reopen the MSYS MinGW shell via `MSYS2 MinGW 64-bit` shortcut on
  64-bit Windows or `MSYS2 MinGW 32-bit` shortcut on 32-bit Windows. Note 
  that if you are running 64-bit Windows, you will have both 64-bit and
  32-bit MinGW shells.

**Cloning**

* To git clone, run:

    ```bash
    git clone --recursive https://github.com/oxen-io/oxen-core.git
    ```

**Building**

* Change to the cloned directory, run:
	
    ```bash
    cd oxen-core
    ```

* If you would like a specific [version/tag](https://github.com/oxen-io/oxen-core/tags), do a git checkout for that version. eg. 'v5.1.2'. If you don't care about the version and just want binaries from master, skip this step:
	
    ```bash
    git checkout v5.1.2
    ```

* If you are on a 64-bit system, run:

    ```bash
    make release-static-win64
    ```

* If you are on a 32-bit system, run:

    ```bash
    make release-static-win32
    ```

* The resulting executables can be found in `build/<MinGW version>/<oxen version>/release/bin`

* **Optional**: to build Windows binaries suitable for debugging on a 64-bit system, run:

    ```bash
    make debug-static-win64
    ```

* **Optional**: to build Windows binaries suitable for debugging on a 32-bit system, run:

    ```bash
    make debug-static-win32
    ```

* The resulting executables can be found in `build/<MinGW version>/<oxen version>/debug/bin`

### On FreeBSD:

The project can be built from scratch by following instructions for Linux above(but use `gmake` instead of `make`). 
If you are running Oxen in a jail, you need to add `sysvsem="new"` to your jail configuration, otherwise lmdb will throw the error message: `Failed to open lmdb environment: Function not implemented`.

### On OpenBSD:

You will need to add a few packages to your system. `pkg_add cmake gmake zeromq cppzmq libiconv boost`.

The `doxygen` and `graphviz` packages are optional and require the xbase set.
Running the test suite also requires `py-requests` package.

Build oxen: `env DEVELOPER_LOCAL_TOOLS=1 BOOST_ROOT=/usr/local gmake release-static`

Note: you may encounter the following error, when compiling the latest version of oxen as a normal user:

```
LLVM ERROR: out of memory
c++: error: unable to execute command: Abort trap (core dumped)
```

Then you need to increase the data ulimit size to 2GB and try again: `ulimit -d 2000000`

### On Solaris:

The default Solaris linker can't be used, you have to install GNU ld, then run cmake manually with the path to your copy of GNU ld:

```bash
mkdir -p build/release
cd build/release
cmake -DCMAKE_LINKER=/path/to/ld -D CMAKE_BUILD_TYPE=Release ../..
cd ../..
```

Then you can run make as usual.

### On Linux for Android (using docker):

```bash
# Build image (for ARM 32-bit)
docker build -f utils/build_scripts/android32.Dockerfile -t oxen-android .
# Build image (for ARM 64-bit)
docker build -f utils/build_scripts/android64.Dockerfile -t oxen-android .
# Create container
docker create -it --name oxen-android oxen-android bash
# Get binaries
docker cp oxen-android:/src/build/release/bin .
```

### Building portable statically linked binaries

By default, in either dynamically or statically linked builds, binaries target the specific host processor on which the build happens and are not portable to other processors. Portable binaries can be built using the following targets:

* ```make release-static-linux-x86_64``` builds binaries on Linux on x86_64 portable across POSIX systems on x86_64 processors
* ```make release-static-linux-i686``` builds binaries on Linux on x86_64 or i686 portable across POSIX systems on i686 processors
* ```make release-static-linux-armv8``` builds binaries on Linux portable across POSIX systems on armv8 processors
* ```make release-static-linux-armv7``` builds binaries on Linux portable across POSIX systems on armv7 processors
* ```make release-static-linux-armv6``` builds binaries on Linux portable across POSIX systems on armv6 processors
* ```make release-static-win64``` builds binaries on 64-bit Windows portable across 64-bit Windows systems
* ```make release-static-win32``` builds binaries on 64-bit or 32-bit Windows portable across 32-bit Windows systems

### Cross Compiling

You can also cross-compile static binaries on Linux for Windows and macOS with the `depends` system.

* ```make depends target=x86_64-linux-gnu``` for 64-bit linux binaries.
* ```make depends target=x86_64-w64-mingw32``` for 64-bit windows binaries.
  * Requires: `python3 g++-mingw-w64-x86-64 wine1.6 bc`
* ```make depends target=x86_64-apple-darwin11``` for macOS binaries.
  * Requires: `cmake imagemagick libcap-dev librsvg2-bin libz-dev libbz2-dev libtiff-tools python-dev`
* ```make depends target=i686-linux-gnu``` for 32-bit linux binaries.
  * Requires: `g++-multilib bc`
* ```make depends target=i686-w64-mingw32``` for 32-bit windows binaries.
  * Requires: `python3 g++-mingw-w64-i686`
* ```make depends target=arm-linux-gnueabihf``` for armv7 binaries.
  * Requires: `g++-arm-linux-gnueabihf`
* ```make depends target=aarch64-linux-gnu``` for armv8 binaries.
  * Requires: `g++-aarch64-linux-gnu`
* ```make depends target=riscv64-linux-gnu``` for RISC V 64 bit binaries.
  * Requires: `g++-riscv64-linux-gnu`

The required packages are the names for each toolchain on apt. Depending on your distro, they may have different names.

Using `depends` might also be easier to compile Oxen on Windows than using MSYS. Activate Windows Subsystem for Linux (WSL) with a distro (for example Ubuntu), install the apt build-essentials and follow the `depends` steps as depicted above.

The produced binaries still link libc dynamically. If the binary is compiled on a current distribution, it might not run on an older distribution with an older installation of libc. Passing `-DBACKCOMPAT=ON` to cmake will make sure that the binary will run on systems having at least libc version 2.17.

## Installing Oxen from a package

Pre-built packages are available for recent Debian and Ubuntu systems (and are often usable on
Debian or Ubuntu-derived Linux distributions).  For more details see https://deb.imaginary.stream



You can also build a docker package using:

    ```bash
    # Build using all available cores
    docker build -t oxen-daemon-image .
    
    # or build using a specific number of cores (reduce RAM requirement)
    docker build --build-arg NPROC=1 -t oxen .
    
    # either run in foreground
    docker run -it -v /oxen/chain:/root/.oxen -v /oxen/wallet:/wallet -p 22022:22022 oxen 
    
    # or in background
    docker run -it -d -v /oxen/chain:/root/.oxen -v /oxen/wallet:/wallet -p 22022:22022 oxen 
    ```

* The build needs 3 GB space.
* Wait one hour or more. For docker, the collect_from_docker_container.sh script will automate downloading the binaries from the docker container.

## Running oxend

The build places the binary in `bin/` sub-directory within the build directory
from which cmake was invoked (repository root by default). To run in
foreground:

```bash
./bin/oxend
```

To list all available options, run `./bin/oxend --help`.  Options can be
specified either on the command line or in a configuration file passed by the
`--config-file` argument.  To specify an option in the configuration file, add
a line with the syntax `argumentname=value`, where `argumentname` is the name
of the argument without the leading dashes, for example `log-level=1`.

To run in background:

```bash
./bin/oxend --log-file oxend.log --detach
```

To run as a systemd service, copy
[oxend.service](utils/systemd/oxend.service) to `/etc/systemd/system/` and
[oxend.conf](utils/conf/oxend.conf) to `/etc/`. The [example
service](utils/systemd/oxend.service) assumes that the user `oxen` exists
and its home is the data directory specified in the [example
config](utils/conf/oxend.conf).

If you're on Mac, you may need to add the `--max-concurrency 1` option to
oxen-wallet-cli, and possibly oxend, if you get crashes refreshing.

## Internationalization

See [README.i18n.md](README.i18n.md).

## Debugging

This section contains general instructions for debugging failed installs or problems encountered with Oxen. First ensure you are running the latest version built from the Github repo.

### Obtaining stack traces and core dumps on Unix systems

We generally use the tool `gdb` (GNU debugger) to provide stack trace functionality, and `ulimit` to provide core dumps in builds which crash or segfault.

* To use `gdb` in order to obtain a stack trace for a build that has stalled:

Run the build.

Once it stalls, enter the following command:

```bash
gdb /path/to/oxend `pidof oxend`
```

Type `thread apply all bt` within gdb in order to obtain the stack trace

* If however the core dumps or segfaults:

Enter `ulimit -c unlimited` on the command line to enable unlimited filesizes for core dumps

Enter `echo core | sudo tee /proc/sys/kernel/core_pattern` to stop cores from being hijacked by other tools

Run the build.

When it terminates with an output along the lines of "Segmentation fault (core dumped)", there should be a core dump file in the same directory as oxend. It may be named just `core`, or `core.xxxx` with numbers appended.

You can now analyse this core dump with `gdb` as follows:

```bash
gdb /path/to/oxend /path/to/dumpfile`
```

Print the stack trace with `bt`

 * If a program crashed and cores are managed by systemd, the following can also get a stack trace for that crash:

```bash
coredumpctl -1 gdb
```

#### To run Oxen within gdb:

Type `gdb /path/to/oxend`

Pass command-line options with `--args` followed by the relevant arguments

Type `run` to run oxend

### Analysing memory corruption

There are two tools available:

#### ASAN

Configure Oxen with the -D SANITIZE=ON cmake flag, eg:

```bash
cd build/debug && cmake -D SANITIZE=ON -D CMAKE_BUILD_TYPE=Debug ../..
```

You can then run the oxen tools normally. Performance will typically halve.

#### valgrind

Install valgrind and run as `valgrind /path/to/oxend`. It will be very slow.

### LMDB

Instructions for debugging suspected blockchain corruption as per @HYC

There is an `mdb_stat` command in the LMDB source that can print statistics about the database but it's not routinely built. This can be built with the following command:

```bash
cd ~/oxen/external/db_drivers/liblmdb && make
```

The output of `mdb_stat -ea <path to blockchain dir>` will indicate inconsistencies in the blocks, block_heights and block_info table.

The output of `mdb_dump -s blocks <path to blockchain dir>` and `mdb_dump -s block_info <path to blockchain dir>` is useful for indicating whether blocks and block_info contain the same keys.

These records are dumped as hex data, where the first line is the key and the second line is the data.

# Known Issues

## Protocols

### Socket-based

Because of the nature of the socket-based protocols that drive Oxen, certain protocol weaknesses are somewhat unavoidable at this time. While these weaknesses can theoretically be fully mitigated, the effort required (the means) may not justify the ends. As such, please consider taking the following precautions if you are a Oxen node operator:

- Run `oxend` on a "secured" machine. If operational security is not your forte, at a very minimum, have a dedicated a computer running `oxend` and **do not** browse the web, use email clients, or use any other potentially harmful apps on your `oxend` machine. **Do not click links or load URL/MUA content on the same machine**. Doing so may potentially exploit weaknesses in commands which accept "localhost" and "127.0.0.1".
- If you plan on hosting a public "remote" node, start `oxend` with `--restricted-rpc`. This is a must.

### Blockchain-based

Certain blockchain "features" can be considered "bugs" if misused correctly. Consequently, please consider the following:

- When receiving Oxen, be aware that it may be locked for an arbitrary time if the sender elected to, preventing you from spending that Oxen until the lock time expires. You may want to hold off acting upon such a transaction until the unlock time lapses. To get a sense of that time, you can consider the remaining blocktime until unlock as seen in the `show_transfers` command.
