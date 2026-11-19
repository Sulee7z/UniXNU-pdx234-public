#!/usr/bin/env bash
# Linux host-only linker selection. Kernel compilation flags stay unchanged.
set -euo pipefail
exec "${UNIXNU_LOCAL_CLANGXX:?}" -nostdlib "-fuse-ld=${UNIXNU_LOCAL_LD:?}" "$@"
