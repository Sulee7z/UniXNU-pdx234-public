#!/usr/bin/env bash
# Recompile source and relink using only the restored handoff inputs.
set -euo pipefail

if [[ ${1:-} != --inside ]]; then
    if [[ $# != 2 ]]; then
        echo 'Usage: sudo bash rebuild-incremental.sh EXTRACTED_HANDOFF NEW_RESULTS_DIRECTORY' >&2
        exit 2
    fi
    capsule=$(realpath -- "$1")
    python3 -B "$capsule/check-handoff.py"
    python3 -B "$capsule/check-incremental.py"
    mkdir -- "$2"
    results=$(realpath -- "$2")
    sandbox=$(mktemp -d /run/pdx071-incremental.XXXXXX)
    trap 'rmdir "$sandbox/input" "$sandbox/results" "$sandbox"' EXIT
    mkdir "$sandbox/input" "$sandbox/results"
    unshare --mount --propagation private -- bash "$capsule/rebuild-incremental.sh" --inside "$capsule" "$results" "$sandbox"
    exit
fi

capsule=$2
results=$3
sandbox=$4
artifact=UniXNU-Port-artifacts/platform069-20261118
mkdir -p "$capsule/layout/mnt/f/$artifact/handoff-results"
for source in sheng UniXNU; do
    git_dir="$capsule/layout/mnt/f/$artifact/$source/.git"
    if [[ ! -e "$git_dir" ]]; then
        git clone --bare "$capsule/git/$source.bundle" "$git_dir"
    fi
done
mount --bind "$capsule" "$sandbox/input"
mount --bind "$results" "$sandbox/results"
mount -t tmpfs -o mode=0755 tmpfs /mnt
for drive in e f g; do mkdir "/mnt/$drive"; done
mkdir -p /root/unixnu-build /root/unixnu-toolchain
for target in /mnt/e /mnt/f /mnt/g /root/unixnu-build /root/unixnu-toolchain; do
    mount --bind "$sandbox/input/layout$target" "$target"
    mount -o remount,bind,ro "$target"
done
mount --bind "$sandbox/results" "/mnt/f/$artifact/handoff-results"
cd /mnt/g/UniXNU-Port/ports/UniXNU-pdx234
exec python3 -B scripts/ci/rebuild-sony-platform071.py --out "/mnt/f/$artifact/handoff-results/incremental"
