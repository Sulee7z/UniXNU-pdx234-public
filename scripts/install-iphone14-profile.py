#!/usr/bin/env python3
"""Install this device's audited input profile beside the official profiles without changing them."""
import hashlib
import json
from pathlib import Path
import shutil

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
NAME = 'ios-27.0.1-24A446-iphone14'


def main():
    source = DEVICE / 'profiles' / NAME
    destination = PROJECT / 'references/xperia-mainline-20261107/profiles/os' / NAME
    if destination.exists():
        raise RuntimeError('Preserve the existing local profile installation')
    shutil.copytree(source, destination)
    entries = [{'path': str(path.relative_to(source)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
               for path in sorted(source.rglob('*')) if path.is_file()]
    (DEVICE / 'evidence/iphone14-profile-installation.json').write_text(json.dumps(dict(
        base='b6de3eb11f0b0118dfc14fad6eefc884a3b69737', local_profile=NAME, files=entries,
        xnu_source_follows_official_27=True, ipad_root_uuids_or_addresses_reused=False,
        runtime_verified=False), indent=2))
    print('Installed independent iPhone14 iOS27 input profile:', destination)


if __name__ == '__main__':
    main()
