#!/usr/bin/env python3
"""Audit the withdrawn 067 artifact and its retained readback receipts only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = Path('/mnt/f/UniXNU-Port-artifacts/platform067-20261118')
RELEASE = ROOT / 'out/d27-pac-abi-release-20261118-067'


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()

    release_path = RELEASE / 'release.json'
    release = json.loads(release_path.read_text())
    image = RELEASE / Path(release['image']).name
    delivery_path = ROOT / 'evidence/d27-platform067-delivery.json'
    delivery = json.loads(delivery_path.read_text())
    withdrawn_path = RELEASE / 'withdrawn-menu-request.json'
    withdrawn = json.loads(withdrawn_path.read_text())

    require(release['label'] == 'PAC-ABI-067', 'Unexpected 067 release identity')
    require(image.stat().st_size == release['bytes'] == delivery['bytes'], '067 image size differs')
    image_sha = sha(image)
    require(image_sha == release['sha256'] == delivery['sha256'] == withdrawn['image_sha256'],
            '067 image SHA256 differs across release/withdrawal records')
    encoded_args = release['kernel_args'].encode('ascii')
    require(len(encoded_args) == 1041, 'Expected withdrawn 067 command-line fixture')

    sys.path.insert(0, str(ROOT / 'ci'))
    from darwin_boot_args import validate
    try:
        validate(release['kernel_args'])
    except ValueError as error:
        rejection = str(error)
    else:
        raise ValueError('Withdrawn 067 request unexpectedly accepted')
    require('1041' in rejection and '1023' in rejection, 'Unexpected shared boot-argument guard result')
    require(withdrawn['withdrawn'] is True and withdrawn['replaced_by'].endswith('-068'),
            '067 withdrawal marker missing')

    readbacks = []
    for item in delivery['readbacks']:
        path = Path(item['path'])
        require(path.is_file() and sha(path) == item['sha256'], 'Retained readback receipt changed: ' + str(path))
        value = json.loads(path.read_text())
        require(value['image_sha256'] == image_sha and value['hardware_verified'] is False,
                'Readback identity or hardware scope differs: ' + str(path))
        readbacks.append(dict(path=str(path), sha256=item['sha256'], image_sha256=value['image_sha256'],
                              hardware_verified=value['hardware_verified']))

    windows_path = Path(delivery['separate_windows_filehash']['path'])
    require(windows_path.is_file() and sha(windows_path) == delivery['separate_windows_filehash']['sha256'],
            'Separate Windows file-hash receipt changed')
    windows = json.loads(windows_path.read_text())
    require(windows == dict(platform='Windows', image=windows['image'], bytes=release['bytes'], sha256=image_sha),
            'Separate Windows file hash does not match the withdrawn image')

    radio_path = ROOT / 'evidence/d27-platform067-final-radio-readback.json'
    radio = json.loads(radio_path.read_text())
    require(radio['passed'] is True and radio['image_sha256'] == image_sha and
            radio['device_operations'] is False and radio['association_or_pairing_verified'] is False,
            'Final radio payload readback/scope differs')

    audit = dict(
        schema='unixnu.sony-platform067-record-audit.v1',
        passed=True,
        image=dict(path=str(image), bytes=release['bytes'], sha256=image_sha),
        release_receipt=dict(path=str(release_path), sha256=sha(release_path)),
        request=dict(ascii_bytes=len(encoded_args), capacity_bytes=1024, accepted=False,
                     shared_guard_rejection=rejection, withdrawal_marker_verified=True),
        readbacks=readbacks,
        separate_windows_filehash=dict(path=str(windows_path), sha256=sha(windows_path),
                                       platform=windows['platform'], matches_image=True),
        final_radio_readback=dict(path=str(radio_path), sha256=sha(radio_path),
                                  passed=True, hardware_verified=False),
        image_delivery_record_consistent=True,
        hardware_verified=False,
        device_operations=False,
        commits_or_pushes=False,
        scope='Host-only receipt consistency. 067 is withdrawn; this audit does not qualify it as bootable.',
    )
    encoded = json.dumps(audit, indent=2) + '\n'
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        if out.read_text() != encoded:
            raise ValueError('Existing audit receipt differs; preserve it: ' + str(out))
    else:
        out.write_text(encoded)
    print(json.dumps(dict(passed=True, image_sha256=image_sha,
                          rejected_argument_bytes=len(encoded_args), readbacks=len(readbacks),
                          hardware_verified=False, device_operations=False), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
