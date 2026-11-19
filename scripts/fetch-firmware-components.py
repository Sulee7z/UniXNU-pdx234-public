#!/usr/bin/env python3
"""Fetch exact catalog component commits instead of obsolete upstream gitlinks."""
import json
from pathlib import Path
import subprocess
import tomllib

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
MAINLINE = PROJECT / 'references/xperia-mainline-20261107'
ROOT = DEVICE / '.cache/firmware-components'
GIT = PROJECT / 'tools/git/cmd/git.exe'


def main():
    catalog = tomllib.loads((MAINLINE / 'components.toml').read_text())
    specs = next(value for value in catalog.values() if isinstance(value, list) and value and 'id' in value[0])
    selected = {item['id']: item for item in specs if item['id'] in ('DarwinBoot', 'XnuPrelink', 'ArmCpu', 'ArmDTPlatform')}
    ROOT.mkdir(parents=True, exist_ok=True)
    record = dict(mainline='b6de3eb11f0b0118dfc14fad6eefc884a3b69737', reason='catalog pins are canonical; the obsolete ArmCpu gitlink is unavailable', modules=[])
    for name, spec in selected.items():
        path = ROOT / name
        if path.exists():
            raise RuntimeError('Preserve an existing component fetch')
        subprocess.run([str(GIT), 'clone', '--depth', '1', spec['repository'], str(path)], check=True)
        subprocess.run([str(GIT), '-C', str(path), 'fetch', '--depth', '1', 'origin', spec['revision']], check=True)
        subprocess.run([str(GIT), '-C', str(path), 'checkout', '--detach', spec['revision']], check=True)
        actual = subprocess.check_output([str(GIT), '-C', str(path), 'rev-parse', 'HEAD']).decode().strip()
        if actual != spec['revision']:
            raise RuntimeError('Component commit mismatch')
        record['modules'].append(dict(name=name, repository=spec['repository'], commit=actual, path=str(path)))
        (DEVICE / 'evidence/catalog-component-pins.json').write_text(json.dumps(record, indent=2))
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
