# Debian package build, replacing the project's own CI configs on this packaging branch: builds the
# package for each of `arches` and uploads the results to builds.session.codes.
#
# The session-packaging tools read the plain assignments below (distro, builder_image, repo_suffix,
# arches), so keep them on single lines in this form.

distro = "trixie"
distro_name = "Debian " + distro
builder_image = "registry.session.codes/debian-" + distro + "-builder"

# Which deb.session.foundation repo Session dependencies come from: "" (public), "/beta" or
# "/staging".
repo_suffix = "/staging"

arches = ["amd64", "i386", "arm64", "armhf"]

# Debian architecture -> the agent platform it builds on, and its builder image's suffix.
builders = {
    "amd64": ("amd64", ""),
    "i386": ("amd64", "/i386"),
    "arm64": ("arm64", "/arm64v8"),
    "armhf": ("arm64", "/arm32v7"),
}

# Parallel build jobs, by agent platform.
jobs = {"amd64": 6, "arm64": 4}

# Extra agent labels, by agent platform: {"arm64": {"mem8": "yes"}} sends the arm64 builds to the 8GB
# agents rather than possibly a 4GB one, for builds that need the memory.
agent_labels = {"arm64": {"mem8": "yes"}}

apt_get = "apt-get -o=Dpkg::Use-Pty=0 -q"

session_sources = "\n".join([
    "Types: deb",
    "URIs: https://deb.session.foundation" + repo_suffix,
    "Suites: " + distro,
    "Components: main",
    "Signed-By: /usr/share/keyrings/session-foundation.gpg",
])

def deb(arch):
    platform, image_suffix = builders[arch]
    image = builder_image + image_suffix
    return {
        "name": "%s (%s)" % (distro_name, arch),
        "labels": dict({"platform": "linux/" + platform, "backend": "docker"}, **agent_labels.get(platform, {})),
        "when": [{"event": ["push", "manual"]}],
        "steps": [
            {
                "name": "build",
                "image": image,
                "pull": True,
                "commands": [
                    'echo "Building on $${CI_MACHINE}"',
                    'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                    "cp debian/deb.session.foundation.gpg /usr/share/keyrings/session-foundation.gpg",
                    "echo '%s' >/etc/apt/sources.list.d/session.sources" % session_sources,
                    apt_get + " update",
                    apt_get + " install -y eatmydata",
                    "eatmydata " + apt_get + " dist-upgrade -y",
                    "eatmydata " + apt_get + " install --no-install-recommends -y git-buildpackage devscripts equivs g++ ccache",
                    "eatmydata dpkg-reconfigure ccache",
                    "cd debian",
                    'eatmydata mk-build-deps -i -r --tool="' + apt_get + ' -o Debug::pkgProblemResolver=yes --no-install-recommends -y" control',
                    "cd ..",
                    "eatmydata gbp buildpackage --git-no-pbuilder --git-builder='debuild --prepend-path=/usr/lib/ccache --preserve-envvar=CCACHE_*' --git-upstream-tag=HEAD -us -uc -b -j%d" % jobs[platform],
                ],
            },
            {
                # Kept out of the build step so that the upstream build never sees the key.
                "name": "upload",
                "image": image,
                "environment": {"SSH_KEY": {"from_secret": "SSH_KEY"}},
                "commands": [
                    apt_get + " update",
                    apt_get + " install --no-install-recommends -y openssh-client",
                    "./debian/ci-upload.sh %s %s" % (distro, arch),
                ],
            },
        ],
    }

def main(ctx):
    return [deb(arch) for arch in arches]
