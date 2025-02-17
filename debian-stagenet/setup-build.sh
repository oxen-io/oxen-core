#!/bin/bash

set -e

if ! [ -f debian/rules ] || ! [ -f debian/control.in ]; then
    if [ -f rules ] && [ -f control.in ]; then
        cd ..
    else
        echo "Error: must run from oxen or oxen/debian directory" >&2
        exit 1
    fi
fi

# DEBIAN_CODENAME for the changelog entry, e.g. unstable, trixie, jammy
if [ -z "$DEBIAN_CODENAME" ]; then
    echo "Error: DEBIAN_CODENAME must be set" >&2
    exit 1
fi
if [ -z "$DEBIAN_SUFFIX" ] || [ "${DEBIAN_SUFFIX:0:1}" != "-" ]; then
    echo "Error: DEBIAN_SUFFIX must be set, typically -1 for debian/sid, -1~deb12 (or similar) for debian distros, -1~ubuntu2404 (or similar) for Ubuntu"
fi

OXEN_VERSION=$(grep '^project(' -A 3 CMakeLists.txt | grep '^ *VERSION' | sed -e 's/ *VERSION //')
if [ -z "$OXEN_VERSION" ]; then
    echo "Failed to extract version from CMakeLists.txt!"
    exit 1
fi

sed -e "
s/@LIBOXEN_VERSION@/$OXEN_VERSION/g;
s/@OXEN_APPEND_DEPS@/$OXEN_APPEND_DEPS/g;
s/@IF_FMT \([^@]*\)@/${WITH_FMT:+\\1}/g;
s/@IF_SPD \([^@]*\)@/${WITH_SPD:+\\1}/g;
s/@IF_SECP \([^@]*\)@/${WITH_SECP:+\\1}/g;
" debian/control.in >debian/control

timestamp=${DRONE_BUILD_STARTED:-$(date +%s)}
date_ver=$(date -u -d "@$timestamp" '+%Y%m%d%H%M%S')
date_changelog=$(date -d "@$timestamp" -R)
git_commit=${DRONE_COMMIT:-$(git rev-parse HEAD)}
git_commit_short=${git_commit:0:6}
pkg_ver=$OXEN_VERSION~dev$date_ver~git$git_commit_short${DEBIAN_SUFFIX:-1}

cat <<CHANGELOG >debian/changelog
oxen-snapshot ($pkg_ver) ${DEBIAN_CODENAME:-unstable}; urgency=medium

  * Snapshot build
  * Commit $git_commit

 -- Oxen Project <team@oxen.io>  $date_changelog
CHANGELOG

for sublib in "" "-wallet"; do
    rm -f debian/liboxen-snapshot$sublib[0-9]*.install
    sed -e "s/@LIBOXEN_VER@/$OXEN_VERSION/" debian/liboxen$sublib-snapshot.install.in >debian/liboxen$sublib-snapshot$OXEN_VERSION.install
done
