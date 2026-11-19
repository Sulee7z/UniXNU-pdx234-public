#!/usr/bin/env python3
"""Compile and relink the qualified authenticated event implementation compare."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
sys.path.insert(0, str(ROOT / 'ci'))
from qemu.workloop_event_classification import adapt_source
from compile_dependencies import run_recorded, valid


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--from-work', type=Path, default=BASE / 'qemu-current-20261117-007')
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    if shutil.disk_usage('/mnt/g').free < 8 * 1024**3:
        raise ValueError('G reserve below8GiB')
    before = json.loads((a.from_work / 'native/result.json').read_text())
    if sha(a.from_work / 'native/native.macho') != before['native_sha256']:
        raise ValueError('Completed current virtual kernel required')
    plan = json.loads((BASE / 'native-screen007-055-001/plan.json').read_text())
    job = next(j for j in plan['jobs'] if Path(j['source']).name == 'IOWorkLoop.cpp')
    source = Path(job['source'])
    if sha(source) != job['source_sha256']:
        raise ValueError('Original source identity changed')
    # Qualify the exact source vtable relocation used by runEventSources, against
    # compiled IOEventSource and every concrete PM queue's authenticated entries.
    sys.path.insert(0, str(ROOT / 'ci/XnuPrelink'))
    from kc_image import Image
    table_names = ('__ZTV13IOEventSource', '__ZTV13IOCommandGate', '__ZTV16IOPMRequestQueue',
                   '__ZTV13IOPMWorkQueue', '__ZTV19IOPMCompletionQueue')
    strict_image = Image((a.from_work / 'strict/kernel.macho').read_bytes())
    native = Image(strict_image.data, strict_image.entries['com.apple.kernel'][1])
    symbols = {n: address for address, names in native.symbols().items() for n in names}
    fixups = strict_image.fixups()
    rows = []
    for name in table_names:
        if name not in symbols:
            raise ValueError('Missing actual native PM table: ' + name)
        slot = symbols[name] + 16 + 16 * 8
        target, auth, key, div, addr = fixups[slot]
        if (auth, key, div, addr) != (1, 0, 0x234e, 1):
            raise ValueError('checkForWork slot authentication differs: ' + name)
        rows.append(dict(table=name, slot=16, site=hex(slot), target=hex(target), diversity='0x234e'))
    if rows[0]['target'] != rows[1]['target'] or any(row['target'] == rows[0]['target'] for row in rows[2:]):
        raise ValueError('PM queues must override the passive base checkForWork implementation')
    a.out.mkdir(parents=True, exist_ok=False)
    out = a.out / 'native'
    out.mkdir()
    adapted = out / 'IOWorkLoop.cpp'
    adapted.write_text(adapt_source(source.read_text()))
    obj = out / 'IOWorkLoop.cpo'
    command = list(job['command'])
    command[command.index(job['source'])] = str(adapted)
    command[command.index('-o') + 1] = str(obj)
    with (out / 'compile.log').open('x') as log:
        done = run_recorded(command, cwd=job['directory'], stdout=log, stderr=subprocess.STDOUT, timeout=180)
    if done.returncode:
        raise RuntimeError((out / 'compile.log').read_text()[-10000:])
    deps_path = obj.with_name(obj.name + '.dependencies.json')
    if not valid(json.loads(deps_path.read_text())):
        raise ValueError('Native compile dependencies changed')
    save(out / 'compile-command.json', command)
    command = json.loads((a.from_work / 'native/native-link.command.json').read_text())
    old_list = Path(command[command.index('-filelist') + 1])
    files = old_list.read_text().splitlines()
    if files.count(job['output']) != 1:
        raise ValueError('Unique actual IOWorkLoop object required')
    files[files.index(job['output'])] = str(obj)
    new_list = out / 'link.filelist'
    new_list.write_text('\n'.join(files) + '\n')
    command[command.index('-filelist') + 1] = str(new_list)
    command[command.index('-o') + 1] = str(out / 'native.macho')
    save(out / 'native-link.command.json', command)
    env = dict(os.environ, CROSS_CLANG=plan['compiler'], DARWIN_TRIPLE='arm64e-apple-ios27.0',
               CROSS_EXTRA_FLAGS=before['pac_flag'], TMPDIR=str(out), PYTHONDONTWRITEBYTECODE='1')
    env['PATH'] = str(Path(command[0]).parent) + ':' + env['PATH']
    with (out / 'native-link.log').open('x') as log:
        done = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    if done.returncode:
        raise RuntimeError((out / 'native-link.log').read_text()[-10000:])
    result = copy.deepcopy(before)
    result.update(native=str(out / 'native.macho'), native_sha256=sha(out / 'native.macho'),
                  qemu_workloop_event_classification=True, runtime_qualified=False)
    result['native_source_patches'].append(dict(native_source_patch='qemu-workloop-event-classification',
        original_source=str(source), original_source_sha256=sha(source), source=str(adapted),
        source_sha256=sha(adapted)))
    from native_source_overlays import validate_overlays
    validate_overlays(result, sha)
    save(out / 'result.json', result)
    save(a.out / 'classification-qualification.json', dict(
        source_sha256=sha(source), adapted_source_sha256=sha(adapted), object=str(obj), object_sha256=sha(obj),
        dependency_receipt=str(deps_path), dependency_sha256=sha(deps_path),
        vtable_slots=rows, pac_authentication_retained=True, vtable_entries_written=False,
        native_sha256=result['native_sha256'], runtime_qualified=False))
    print(json.dumps(dict(native=str(out / 'native.macho'), sha256=result['native_sha256'],
                          authenticated_slot=16, diversity='0x234e'), indent=2), flush=True)


if __name__ == '__main__':
    main()
