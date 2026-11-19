#!/usr/bin/env python3
"""Rebuild signed supplicant with bounded startup readiness retry."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'ci'))
from platform069.codesign import inspect
from platform069.integration import sha
from platform069.recovery070 import adapt_supplicant

ARTIFACTS = Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118')
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
PREVIOUS = ARTIFACTS / 'wifi-supplicant069-001'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    out = parser.parse_args().out.resolve()
    if not out.is_relative_to(ARTIFACTS):
        raise ValueError('Use a new F artifact directory')
    old = json.loads((PREVIOUS / 'result.json').read_text())
    if sha(old['binary']) != old['sha256']:
        raise ValueError('069 supplicant changed')
    backend = 'component/userspace/driver_sheng.c'
    config = 'component/out/wpa-src/wpa_supplicant/.config'
    if (sha(PREVIOUS / backend) != 'f9d9e52dceefe2889f69d9a4a1e8f69cc0c2cac74d03a2c3349352301ce64e3e' or
            sha(PREVIOUS / config) != 'eeeda650b01ad4bd22e8b75a8ab7de37f9dd2b7ae3e17856cfee80c55f0f2e17'):
        raise ValueError('Unexpected driver or wpa build profile')
    out.mkdir(exist_ok=False)
    shutil.copytree(PREVIOUS / 'component', out / 'component', symlinks=True)
    (out / backend).write_text(adapt_supplicant((PREVIOUS / backend).read_text()))
    ent = PREVIOUS / 'entitlements.plist'
    signer = Path(json.loads((BASE / 'user-signing-001/source.json').read_text())['executable'])
    command = [arg.replace(str(PREVIOUS), str(out)) for arg in old['command']]
    cwd = (out / config).parent
    with (out / 'build.log').open('xb') as log:
        subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
    binary = out / 'unixnu-wpa_supplicant'
    shutil.copyfile(cwd / 'wpa_supplicant', binary)
    binary.chmod(0o755)
    sign = [str(signer), 'sign', '--digest', 'sha256', '--binary-identifier',
            'org.unixnu.wifi.supplicant', '--entitlements-xml-file', str(ent), str(binary)]
    with (out / 'sign.log').open('xb') as log:
        subprocess.run(sign, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
    sig = inspect(binary)
    ent_hash = hashlib.sha256(sig.pop('entitlements')).hexdigest()
    if ent_hash != old['entitlements_sha256']:
        raise ValueError('Supplicant entitlements changed')
    record = dict(passed=True, target=old['target'], binary=str(binary), sha256=sha(binary),
        signature=sig, entitlements_sha256=ent_hash, command=command, sign=sign,
        inputs={str(p): sha(p) for p in (PREVIOUS / backend, PREVIOUS / config, out / backend, ent, signer)},
        hardware_verified=False, device_operations=False)
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record[k] for k in ('binary', 'sha256', 'signature')}))


if __name__ == '__main__':
    main()
