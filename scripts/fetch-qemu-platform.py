#!/usr/bin/env python3
"""Fetch the exact shared virtual-platform source; do not modify existing checkouts."""
import json
from pathlib import Path
import subprocess

ROOT = Path('/root/unixnu-build/pdx234-qemu-components/ArmVirtPlatform')
PIN = 'd1423a8bceac4be0478a93d9173587111c040084'
URL = 'https://github.com/UniXNU/ArmVirtPlatform.git'


def main() -> None:
    if ROOT.exists():
        raise RuntimeError('Preserve the existing virtual-platform checkout')
    ROOT.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'clone', '--depth', '1', URL, str(ROOT)], check=True)
    subprocess.run(['git', '-C', str(ROOT), 'fetch', '--depth', '1', 'origin', PIN], check=True)
    subprocess.run(['git', '-C', str(ROOT), 'switch', '--detach', 'FETCH_HEAD'], check=True)
    actual = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != PIN:
        raise RuntimeError('Virtual-platform source pin changed')
    print(json.dumps(dict(path=str(ROOT), source=URL, commit=actual), indent=2))


if __name__ == '__main__':
    main()
