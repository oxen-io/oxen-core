#!/usr/bin/env bash

set -o errexit

if [ -z "$SSH_KEY" ]; then
    echo -e "\n\n\n\e[31;1mUnable to upload artifact: SSH_KEY not set\e[0m"
    # Just warn but don't fail, so that this doesn't trigger a build failure for untrusted builds
    exit 0
fi

echo "$SSH_KEY" >ssh_key

set -o xtrace  # Don't start tracing until *after* we write the ssh key

chmod 600 ssh_key

filenames=(dist/electron/Packaged/loki-electron-wallet-*)
if [ "${#filenames[@]}" -lt 1 ] || ! [ -f "${filenames[0]}" ]; then
    echo "Did not find expected electron wallet packages"
    find loki-electron-gui-wallet/dist/electron/Packaged
    exit 1
fi

# sftp doesn't have any equivalent to mkdir -p, so we have to split the above up into a chain of
# -mkdir a/, -mkdir a/b/, -mkdir a/b/c/, ... commands.  The leading `-` allows the command to fail
# without error.
branch_or_tag=${DRONE_BRANCH:-${DRONE_TAG:-unknown}}
upload_to="builds.lokinet.dev/${DRONE_REPO// /_}/${branch_or_tag// /_}"
upload_dirs=(${upload_to//\// })
sftpcmds=
dir_tmp=""
for p in "${upload_dirs[@]}"; do
    dir_tmp="$dir_tmp$p/"
    sftpcmds="$sftpcmds
-mkdir $dir_tmp"
done
for filename in "${filenames[@]}"; do
    sftpcmds="$sftpcmds
put $filename $upload_to"
done

sftp -i ssh_key -b - -o StrictHostKeyChecking=off drone@builds.lokinet.dev <<SFTP
$sftpcmds
SFTP

set +o xtrace

for f in "${filenames[@]}"; do
    echo -e "\n\n\n\n\e[32;1mUploaded to https://${upload_to}/${f}\e[0m\n\n\n"
done
