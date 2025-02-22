#!/usr/bin/env bash
test "x$IGNORE" != "x" && exit 0
set -e
repo=$(readlink -e $(dirname $0)/../)
clang-format-16 -i $(find $repo/{src,pybind} | grep -E '\.[hc](pp)?$')
jsonnetfmt -i $repo/.drone.jsonnet
git --no-pager diff --exit-code --color || (echo -ne '\n\n\e[31;1mLint check failed; please run ./contrib/format.sh\e[0m\n\n' ; exit 1)
