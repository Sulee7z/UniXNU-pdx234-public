#!/usr/bin/env python3
"""Fetch the actual iPhone14 iOS27 build identity and small verified input members."""
import hashlib
import json
from pathlib import Path
import plistlib
import sys
from types import SimpleNamespace

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
MAINLINE = PROJECT / 'references/xperia-mainline-20261107'
sys.path.insert(0, str(MAINLINE / 'scripts'))
from unixnu.ipsw import Ipsw


def main():
    target = json.loads((DEVICE / 'evidence/target-ios27-iphone14.json').read_text())
    config = {name: target[name] for name in ('product', 'device_class', 'chip_id', 'board_id')}
    config.update(url=target['ipsw_url'], version=target['chosen_version'], build=target['chosen_build'])
    root = DEVICE / '.cache/iphone14-ios27'
    root.mkdir(parents=True, exist_ok=True)
    context = SimpleNamespace(board={'ipsw': config}, out_root=root)
    source = Ipsw(context, spec=config['url'])
    saved_manifest = root / 'BuildManifest.plist'
    saved_manifest.write_bytes(plistlib.dumps(source.manifest))
    report = dict(target=config, identity=source.identity['Info'], components={}, phone_operations=False,
                  source_device_ids={'ApChipID': source.identity['ApChipID'], 'ApBoardID': source.identity['ApBoardID']},
                  build_manifest_sha256=hashlib.sha256(saved_manifest.read_bytes()).hexdigest(),
                  whole_archive_sha256_verified=False)
    for component in ('KernelCache', 'DeviceTree', 'StaticTrustCache', 'Cryptex1,SystemTrustCache'):
        path = source.extract(component)
        record = json.loads(path.with_suffix(path.suffix + '.json').read_text())
        report['components'][component] = dict(record, path=str(path), zip_crc_checked=True)
        (root / 'inputs.json').write_text(json.dumps(report, indent=2))
    for component in ('OS', 'Cryptex1,SystemOS', 'Cryptex1,AppOS'):
        try:
            name, size, compressed = source.info(component)
        except Exception:
            continue
        report.setdefault('volume_members', {})[component] = dict(member=name, bytes=size, compressed_bytes=compressed)
    report['result'] = 'iPhone14-build-identity-and-small-inputs-verified'
    (root / 'inputs.json').write_text(json.dumps(report, indent=2))
    with (DEVICE / 'evidence/iphone14-ios27-input-inventory.json').open('x') as output:
        json.dump(report, output, indent=2)
    print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
