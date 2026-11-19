#!/usr/bin/env bash
# Isolated compiler source; keep the installed compiler and every failed build intact.
set -euo pipefail
ROOT=/root/unixnu-build/pdx234-pac-clang
OUT=/mnt/g/UniXNU-Port/ports/UniXNU-pdx234/out/pac-clang-source-001
test ! -e "$ROOT"
test ! -e "$OUT"
mkdir -p "$ROOT" "$OUT"
git init -q "$ROOT"
git -C "$ROOT" remote add origin https://github.com/llvm/llvm-project.git
git -C "$ROOT" config remote.origin.promisor true
git -C "$ROOT" config remote.origin.partialclonefilter blob:none
git -C "$ROOT" sparse-checkout init --cone
git -C "$ROOT" sparse-checkout set llvm clang cmake third-party libc
git -C "$ROOT" fetch --depth 1 --filter=blob:none origin 58c46bae21181fb4240cf964461bea738d96d50e > "$OUT/fetch.log" 2>&1
git -C "$ROOT" switch --detach FETCH_HEAD > "$OUT/checkout.log" 2>&1
git -C "$ROOT" apply --check /mnt/g/UniXNU-Port/references/xperia-mainline-20261107/scripts/linux/llvm-xnu-builtin-type.patch
git -C "$ROOT" apply /mnt/g/UniXNU-Port/references/xperia-mainline-20261107/scripts/linux/llvm-xnu-builtin-type.patch
git -C "$ROOT" apply --unidiff-zero --check /mnt/g/UniXNU-Port/ports/UniXNU-pdx234/patches/host/llvm-authenticated-null.patch
git -C "$ROOT" apply --unidiff-zero /mnt/g/UniXNU-Port/ports/UniXNU-pdx234/patches/host/llvm-authenticated-null.patch
git -C "$ROOT" rev-parse HEAD
echo "$ROOT"
