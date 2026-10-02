#!/usr/bin/env bash

# Script used with CI to upload build artifacts (because specifying all this in the CI config is
# too painful).

set -o errexit

if [ -z "$SSH_KEY" ]; then
    echo -e "\n\n\n\e[31;1mUnable to upload artifact: SSH_KEY not set\e[0m"
    # Just warn but don't fail, so that this doesn't trigger a build failure for untrusted builds
    exit 0
fi

echo "$SSH_KEY" >ssh_key

set -o xtrace  # Don't start tracing until *after* we write the ssh key

chmod 600 ssh_key

branch_or_tag=${CI_COMMIT_BRANCH:-${CI_COMMIT_TAG:-unknown}}

upload_to="oxen.rocks/${CI_REPO// /_}/${branch_or_tag// /_}"

filename=
for f in oxen-*.tar.xz oxen-*.zip; do
    if [[ $f != oxen-\** ]]; then
        filename=$f
        break
    fi
done

if [ -z "$filename" ]; then
    echo "Did not find expected oxen-*.tar.xz or .zip!"
    ls -l
    exit 1
fi

# sftp doesn't have any equivalent to mkdir -p, so we have to split the above up into a chain of
# -mkdir a/, -mkdir a/b/, -mkdir a/b/c/, ... commands.  The leading `-` allows the command to fail
# without error.
upload_dirs=(${upload_to//\// })
mkdirs=
dir_tmp=""
for p in "${upload_dirs[@]}"; do
    dir_tmp="$dir_tmp$p/"
    mkdirs="$mkdirs
-mkdir $dir_tmp"
done

sftp -i ssh_key -b - -o StrictHostKeyChecking=off drone@oxen.rocks <<SFTP
$mkdirs
put $filename $upload_to
SFTP

set +o xtrace

echo -e "\n\n\n\n\e[32;1mUploaded to https://${upload_to}/${filename}\e[0m\n\n\n"

