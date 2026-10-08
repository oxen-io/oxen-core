# Linux builds run in our Debian/Ubuntu images on the docker agents, macOS builds directly on the
# Mac agents.  The static builds also package oxen and, for our own pushes and tags, upload the
# package to builds.session.codes.

registry = "registry.session.codes/"

canonical_repo = "oxen-io/oxen-core"

events = ["push", "pull_request", "tag", "manual"]

lib_deps = [
    "libboost-program-options-dev",
    "libboost-serialization-dev",
    "libboost-thread-dev",
    "libcurl4-gnutls-dev",
    "libevent-dev",
    "libgmp-dev",
    "libgtest-dev",
    "libhidapi-dev",
    "libreadline-dev",
    "libsodium-dev",
    "libsqlite3-dev",
    "libssl-dev",
    "libsystemd-dev",
    "libunbound-dev",
    "libunwind8-dev",
    "libusb-1.0-0-dev",
    "libzstd-dev",
    "nettle-dev",
    "pkg-config",
    "python3",
    "qttools5-dev",
]

# Static builds build their own libraries, and just need the tools to do it.
static_deps = [
    "g++",
    "autoconf",
    "automake",
    "file",
    "libtool",
    "make",
    "patch",
    "pkg-config",
    "qttools5-dev",
]

gtest_filter = "-AddressFromURL.Failure:DNSResolver.DNSSEC*"

apt_get = "apt-get -o=Dpkg::Use-Pty=0 -q"

# USE_LTO is given either way because it defaults to on for release builds.
default_cmake = {
    "CMAKE_BUILD_TYPE": "Release",
    "LOCAL_MIRROR": "https://builds.session.codes/deps",
    "USE_LTO": False,
    "BUILD_TESTS": True,
}

# The version string comes from `git describe --tags`, so the clone needs tags (which also makes it
# a full rather than partial clone).  Submodules are left to the submodules step, below, because a
# recursive checkout would drag in uWebSockets' junk.
clone = [{
    "name": "clone",
    "image": "docker.io/woodpeckerci/plugin-git:2",
    "settings": {"tags": True, "recursive": False},
}]

def submodules(image):
    return {
        "name": "submodules",
        "image": image,
        "commands": [
            # uWebSockets includes nearly 900MB of crap via submodules that we don't use and want to
            # clone on every CI job, so do this song and dance to get rid of the junk.
            "git submodule update --init --depth=1 external/uWebSockets",
            "cd external/uWebSockets",
            "git rm fuzzing/seed-corpus",
            "git submodule update --init --depth=1 uSockets",
            "cd uSockets",
            "git rm boringssl lsquic",
            "cd ../../..",
            "git submodule update --init --recursive --depth=1 --jobs=4",
        ],
    }

def cmake_args(opts):
    return " ".join([
        "-D%s=%s" % (k, ("ON" if v else "OFF") if type(v) == "bool" else v)
        for k, v in opts.items()
    ])

# The commands, run from the top of the checkout, that configure and build in build/, check that
# oxend starts, run the test suite if wanted, and then run `package`.
def build_commands(cmake, jobs, oxend, test_oxend, run_tests, package):
    opts = dict(default_cmake)
    opts.update(cmake)
    if run_tests:
        opts["BUILD_TESTS"] = True

    cmds = [
        "mkdir build",
        "cd build",
        "cmake .. -G Ninja " + cmake_args(opts),
        "ninja -j%d -v" % jobs,
    ]
    if test_oxend:
        cmds.append('(sleep 3; echo "status\ndiff\nexit") | TERM=xterm %s --offline --data-dir=startuptest' % oxend)
    if run_tests:
        cmds += [
            "mkdir -v -p $$HOME/.oxen",
            "GTEST_COLOR=1 ctest --output-on-failure -j%d" % jobs,
        ]
    return cmds + package

# Uploads the package left in build/.  The SSH_KEY secret only exists for our own pushes and tags,
# and Woodpecker doesn't resolve secrets for steps that won't run, so this keeps pull requests from
# failing on it.
def upload(image, setup = []):
    return {
        "name": "upload",
        "image": image,
        "environment": {"SSH_KEY": {"from_secret": "SSH_KEY"}},
        "commands": setup + [
            "cd build",
            "../utils/build_scripts/ci-static-upload.sh",
        ],
        "when": [{"event": ["push", "tag", "manual"], "repo": canonical_repo}],
    }

def workflow(name, labels, steps):
    return {
        "name": name,
        "labels": labels,
        "when": [{"event": events}],
        "clone": clone,
        "steps": steps,
    }

def linux(
        name,
        image,
        arch = "amd64",
        deps = ["g++"] + lib_deps,
        cmake = {},
        test_oxend = True,  # Simple oxend offline startup test
        run_tests = False,  # Runs full test suite
        package = [],
        jobs = 6):
    image = registry + image

    labels = {"platform": "linux/" + arch, "backend": "docker"}
    if arch == "arm64":
        # The wallet code is too bloated to compile in parallel on the 4GB Pis
        labels["mem8"] = "yes"

    steps = [
        submodules("docker.io/woodpeckerci/plugin-git:2"),
        {
            "name": "build",
            "image": image,
            "pull": True,
            "environment": {"GTEST_FILTER": gtest_filter},
            "commands": [
                'echo "Building on $${CI_MACHINE}"',
                apt_get + " update",
                apt_get + " install -y eatmydata",
                "eatmydata " + apt_get + " dist-upgrade -y",
                "eatmydata " + apt_get + " install -y --no-install-recommends " +
                " ".join(["cmake", "git", "ninja-build", "ccache"] + (["gdb"] if test_oxend else []) + deps),
            ] + build_commands(
                dict({"CMAKE_CXX_FLAGS": "-fdiagnostics-color=always"}, **cmake),
                jobs,
                "../utils/build_scripts/ci-gdb.sh ./bin/oxend",
                test_oxend,
                run_tests,
                package,
            ),
        },
    ]
    if package:
        # A fresh container from the build image, so it needs sftp installed
        steps.append(upload(image, setup = [
            apt_get + " update",
            apt_get + " install --no-install-recommends -y openssh-client",
        ]))
    return workflow(name, labels, steps)

def clang(version):
    return linux(
        "Debian sid clang-%d (amd64)" % version,
        "debian-sid-clang",
        deps = ["clang-%d" % version, "clang-tools-%d" % version, "llvm-%d" % version] + lib_deps,
        cmake = {
            "CMAKE_C_COMPILER": "clang-%d" % version,
            "CMAKE_CXX_COMPILER": "clang++-%d" % version,
            "USE_LTO": True,
            "BUILD_EVERYTHING": True,
        },
    )

def macos(name, arch, cmake = {}, run_tests = False, package = [], jobs = 6):
    steps = [
        submodules("sh"),
        {
            "name": "build",
            "image": "sh",
            "environment": {"GTEST_FILTER": gtest_filter},
            "commands": [
                # If you don't do this then the C compiler doesn't have an include path containing
                # basic system headers.  WTF apple:
                'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
            ] + build_commands(
                dict({"CMAKE_CXX_FLAGS": "-fcolor-diagnostics", "OXEN_LOGGING_FORCE_SUBMODULES": True}, **cmake),
                jobs,
                "./bin/oxend",
                True,
                run_tests,
                package,
            ),
        },
    ]
    if package:
        steps.append(upload("sh"))
    return workflow(name, {"platform": "darwin/" + arch, "backend": "local"}, steps)

package_tarxz = [
    "../utils/build_scripts/ci-check-static-libs.sh",
    "ninja strip_binaries",
    "ninja create_tarxz",
]

def main(ctx):
    return [
        workflow("lint check", {"platform": "linux/amd64", "backend": "docker"}, [{
            "name": "build",
            "image": registry + "lint",
            "pull": True,
            "commands": [
                'echo "Building on $${CI_MACHINE}"',
                apt_get + " update",
                apt_get + " install -y eatmydata",
                "eatmydata " + apt_get + " install --no-install-recommends -y git clang-format-19",
                "./contrib/ci-format-verify.sh",
            ],
        }]),

        linux("Debian sid with tests (amd64)", "debian-sid", run_tests = True,
              cmake = {"USE_LTO": True, "BUILD_EVERYTHING": True}),
        linux("Debian sid Debug (amd64)", "debian-sid",
              cmake = {"CMAKE_BUILD_TYPE": "Debug", "BUILD_EVERYTHING": True}),
        clang(19),
        linux("Debian stable (i386)", "debian-stable/i386", cmake = {"ARCH_ID": "i386", "ARCH": "i686"}),
        linux("Debian bookworm (amd64)", "debian-bookworm"),
        linux("Ubuntu LTS (amd64)", "ubuntu-lts"),
        linux("Ubuntu latest (amd64)", "ubuntu-rolling"),

        # armhf builds in a 32-bit image on the arm64 agents
        linux("Debian sid (ARM64)", "debian-sid", arch = "arm64", jobs = 3, cmake = {"BUILD_TESTS": False}),
        linux("Debian stable (armhf)", "debian-stable/arm32v7", arch = "arm64", jobs = 3,
              cmake = {"BUILD_TESTS": False, "ARCH_ID": "armhf"}),

        # Static build (on jammy, for an old glibc):
        linux(
            "Static (jammy amd64)",
            "ubuntu-jammy",
            deps = static_deps,
            cmake = {"BUILD_STATIC_DEPS": True, "ARCH": "x86-64", "BUILD_TESTS": False, "USE_LTO": True},
            package = package_tarxz,
        ),
        linux(
            "Static (win64)",
            "debian-win32-cross",
            deps = static_deps + ["g++-mingw-w64-x86-64"],
            cmake = {
                "CMAKE_TOOLCHAIN_FILE": "../cmake/64-bit-toolchain.cmake",
                "BUILD_STATIC_DEPS": True,
                "ARCH": "x86-64",
                "BUILD_TESTS": False,
            },
            test_oxend = False,
            package = ["ninja strip_binaries", "ninja create_zip"],
        ),

        macos("macOS (Release, ARM) with tests", "arm64", run_tests = True),
        macos("macOS (Debug, ARM)", "arm64", cmake = {"CMAKE_BUILD_TYPE": "Debug", "BUILD_DEBUG_UTILS": True}),
        macos("macOS (Release, Intel) with tests", "amd64", run_tests = True),
        macos("macOS (Static, ARM)", "arm64",
              cmake = {"BUILD_STATIC_DEPS": True, "BUILD_TESTS": False, "USE_LTO": True},
              package = package_tarxz),
        macos("macOS (Static, Intel)", "amd64",
              cmake = {"BUILD_STATIC_DEPS": True, "ARCH": "core2", "ARCH_ID": "amd64", "BUILD_TESTS": False, "USE_LTO": True},
              package = package_tarxz),
    ]
