#!/bin/bash

set -e

if [ "$(basename $(pwd))" != "daemon-rpc" ]; then
    echo "Error: you must run this from the docs/daemon-rpc directory" >&2
    exit 1
fi

rm -rf api

docsify init --local api

rm -f api/README.md

if [ -n "$NPM_PACKAGES" ]; then
    npm_dir="$NPM_PACKAGES/lib/node_modules"
elif [ -n "$NODE_PATH" ]; then
    npm_dir="$NODE_PATH"
elif [ -d "$HOME/node_modules" ]; then
    npm_dir="$HOME/node_modules"
elif [ -d "/usr/local/lib/node_modules" ]; then
    npm_dir="/usr/local/lib/node_modules"
else
    echo "Can't determine your node_modules path; set NPM_PACKAGES or NODE_PATH appropriately" >&2
    exit 1
fi

cp $npm_dir/docsify/node_modules/prismjs/components/prism-{json,python}.min.js api/vendor

./rpc-to-markdown.py core_rpc_server_commands_defs.h "$@"

perl -ni.bak -e '
BEGIN { $first = 0; }
if (m{^\s*<script>\s*$} .. m{^\s*</script>\s*$}) {
    if (not $first) {
        $first = false;
        print qq{
  <script>
    window.\$docsify = {
      name: "Oxen Daemon RPC",
      repo: "https://github.com/oxen-io/oxen-core",
      loadSidebar: "sidebar.md",
      subMaxLevel: 2,
      homepage: "index.md",
    }
  </script>\n};
    }
} else {
    s{<title>.*</title>}{<title>Oxen Daemon RPC</title>};
    s{(name="description" content=)"[^"]*"}{$1"Oxen Daemon RPC endpoint documentation"};
    if (m{^\s*</body>}) {
        print qq{
  <script src="vendor/prism-json.min.js"></script>
  <script src="vendor/prism-python.min.js"></script>\n};
    }
    print;
}' api/index.html
