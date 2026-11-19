#!/usr/bin/env python3
"""Fetch original J820 inputs for the isolated official sheng27 control."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path('/root/unixnu-build/sheng27-control-001')
TOOL = Path('/root/unixnu-build/pdx234-tools/ipsw-3.1.743/ipsw')


def sha(path, algorithm='sha256'):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def main():
    profile_path = ROOT / 'UniXNU/profiles/os/ipados-27.0.1-24A446/profile.toml'
    profile = tomllib.loads(profile_path.read_text())
    if (profile['ipsw']['product'], profile['ipsw']['device_class']) != ('iPad17,3', 'j820ap'):
        raise ValueError('Control must retain official J820 system inputs')
    if not TOOL.is_file():
        raise ValueError('Linux AEA decoder is missing')
    sys.path.insert(0, str(ROOT / 'UniXNU/scripts'))
    from unixnu.ipsw import Ipsw
    from types import SimpleNamespace
    context = SimpleNamespace(board=profile, out_root=ROOT / 'inputs')
    source = Ipsw(context, spec=profile['ipsw']['url'])
    output = ROOT / 'inputs'
    output.mkdir(exist_ok=True)
    plain = output / 'plain'
    plain.mkdir(exist_ok=True)
    manifest = source.zip.read('BuildManifest.plist')
    (output / 'BuildManifest.plist').write_bytes(manifest)
    report = {'profile': profile['os']['name'], 'product': 'iPad17,3',
              'build': profile['ipsw']['build'], 'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
              'decoder': str(TOOL), 'decoder_sha256': sha(TOOL),
              'device_operations': False, 'D27_inputs_used': False, 'inputs': []}
    try:
        for component in ['StaticTrustCache', 'Cryptex1,SystemTrustCache',
                          'DeviceTree', 'KernelCache', 'Cryptex1,SystemOS', 'OS']:
            path = source.extract(component)
            record = {'component': component, 'member': source.member(component),
                      'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}
            digest = source.identity['Manifest'][component].get('Digest', b'').hex()
            record['manifest_digest'] = digest
            if path.suffix == '.aea':
                decoded = plain / path.stem
                if not decoded.exists():
                    with (output / (component.replace(',', '-') + '-decrypt.log')).open('xb') as log:
                        subprocess.run([str(TOOL), 'fw', 'aea', str(path), '--output', str(plain)],
                                       stdout=log, stderr=subprocess.STDOUT, check=True)
                prefix = 'systemos' if component == 'Cryptex1,SystemOS' else 'os'
                decoded_sha = sha(decoded)
                if decoded_sha != profile['root'][prefix + '_image_sha256']:
                    raise ValueError('Decoded disk differs from official profile pin: ' + component)
                decoded_sha384 = sha(decoded, 'sha384')
                if digest not in (sha(path, 'sha384'), decoded_sha384):
                    raise ValueError('BuildManifest digest mismatch: ' + component)
                record['decoded'] = {'path': str(decoded), 'sha256': decoded_sha,
                                     'sha384': decoded_sha384, 'bytes': decoded.stat().st_size}
            report['inputs'].append(record)
            (output / 'verified-inputs.json').write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(record), flush=True)
    finally:
        source.zip.close()
        source.stream.close()


if __name__ == '__main__':
    main()
