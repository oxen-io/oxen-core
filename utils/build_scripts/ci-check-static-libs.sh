#!/usr/bin/env bash

# Script used with CI to check that a statically build oxen only links against the expected base
# system libraries.  Expects to be run with pwd of the build directory.

set -o errexit

os="$(uname -s)"

anybad=
for bin in oxend oxen-{wallet-{cli,rpc},gen-trusted-multisig,blockchain-{ancestry,depth,export,import,mark-spent-outputs,stats,usage}}; do
    bad=
    if [ "$os" == "Darwin" ]; then
        if otool -L bin/$bin | grep -Ev '^bin/'$bin':|^\s*(/usr/lib/lib(System|c\+\+|objc)\.|/System/Library/Frameworks/(AppKit|CoreFoundation|IOKit|SystemConfiguration|Security))'; then
            bad=1
        fi
    elif [ "$os" == "Linux" ]; then
        if ldd bin/$bin | grep -Ev '(linux-vdso|ld-linux-x86-64|lib(pthread|dl|rt|stdc\+\+|gcc_s|c|m))\.so'; then
            bad=1
        fi
    else
        echo -e "\n\n\n\n\e[31;1mDon't know how to check linked libs on $os\e[0m\n\n\n"
        exit 1
    fi

    if [ -n "$bad" ]; then
        anybad=1
        echo -e "\n\n\n\n\e[31;1m$bin links to unexpected libraries\e[0m\n\n\n"
    fi
done

if [ -n "$anybad" ]; then
    exit 1
fi

echo -e "\n\n\n\n\e[32;1mNo unexpected linked libraries found\e[0m\n\n\n"
