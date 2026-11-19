#!/usr/bin/env python3
"""Re-emit the strict D27 collection with audited native kmod PAC metadata.

Only a new private prelinker checkout and a new output directory are written.
The source kernel, original kernelcache, naming reference and old candidate
remain unchanged. This does not perform any device operation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')
STRICT_SHA = 'f9516370c3ccd909a083099b4cde1828685d9d0d78ff5b827628937ec07e436b'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    out = args.out.resolve()
    if out.exists():
        p.error('Use a new output directory')
    old = BASE / 'strict-006'
    if sha(old / 'kernel.macho') != STRICT_SHA:
        raise ValueError('Strict baseline changed')
    plan = json.loads((old / 'result.json').read_text())
    for path, digest in plan['inputs'].items():
        if sha(Path(path)) != digest:
            raise ValueError('Input changed: ' + path)
    out.mkdir(parents=True)
    kit = out / 'XnuPrelink'
    shutil.copytree(old / 'XnuPrelink', kit, ignore=shutil.ignore_patterns('__pycache__'))
    helper = DEVICE / 'ci/d27_kmod_pac.py'
    shutil.copyfile(helper, kit / helper.name)
    segmented = kit / 'fileset_segmented.py'
    text = segmented.read_text()
    old_import = 'from fileset_emit import inline_data_ranges, inside\n'
    new_import = ('from fileset_emit import inline_data_ranges, inside, prelink_info\n'
                  'from d27_kmod_pac import entrypoint_sites, converted_pointer\n')
    old_begin = '        reader = ChainReader(self.cache.data, self.cache)\n'
    new_begin = ('        kmod_sites, kmod_records = entrypoint_sites(\n'
                 '            self.cache, prelink_info(self.cache)[1], self.closure, self.native)\n'
                 '        self.report["kmod_pac_abi"] = kmod_records\n' + old_begin)
    old_pointer = '                    pointers[site] = (target, auth, key, diversity, addrdiv)\n'
    new_pointer = ('                    if site in kmod_sites:\n'
                   '                        target, auth, key, diversity, addrdiv = converted_pointer(\n'
                   '                            (target, auth, key, diversity, addrdiv))\n' + old_pointer)
    for before, after in ((old_import, new_import), (old_begin, new_begin), (old_pointer, new_pointer)):
        if text.count(before) != 1:
            raise ValueError('Unexpected prelinker adapter context')
        text = text.replace(before, after, 1)
    segmented.write_text(text)
    compile(text, str(segmented), 'exec')
    command = list(plan['command'])
    command[2] = str(kit / 'emit_prelink.py')
    command[command.index('--output') + 1] = str(out / 'kernel.macho')
    (out / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (out / 'prelink.log').open('x') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError((out / 'prelink.log').read_text()[-6000:])
    report = json.loads((out / 'kernel.json').read_text())
    if report['missing'] or report['stubbed'] or report['allow_missing']:
        raise ValueError('Strict mapping requirements failed')
    records = report['statistics']['kmod_pac_abi']
    expected = {int(record['site'], 16) for record in records}
    sys.path.insert(0, str(kit))
    from kc_image import Image
    baseline = Image((old / 'kernel.macho').read_bytes())
    candidate = Image((out / 'kernel.macho').read_bytes())
    before, after = baseline.fixups(), candidate.fixups()
    if before.keys() != after.keys():
        raise ValueError('Fixup topology changed')
    changed = {site for site in before if before[site] != after[site]}
    if changed != expected:
        raise ValueError('Unexpected changed fixup sites')
    for site in changed:
        a, b = before[site], after[site]
        if a[:3] != b[:3] or a[4] != b[4] or (a[3], b[3]) != (0xE4FE, 0):
            raise ValueError('Target, key or authentication was altered')
    differing = {i for i, (a, b) in enumerate(zip(baseline.data, candidate.data)) if a != b}
    allowed = {baseline.offset(site, 8) + byte for site in changed for byte in (4, 5)}
    if len(candidate.data) != len(baseline.data) or not differing <= allowed:
        raise ValueError('Bytes outside the audited diversifier fields changed')
    result = dict(candidate=str(out / 'kernel.macho'), candidate_sha256=sha(out / 'kernel.macho'),
                  baseline_sha256=STRICT_SHA, adapter_sha256=sha(helper),
                  native_unchanged=True, reference_unchanged=True, original_kext_targets_unchanged=True,
                  pac_authentication_retained=True, changed_fixups=len(changed), changed_bytes=len(differing),
                  only_kmod_diversifiers_changed=True, strict_missing={}, strict_stubbed={},
                  allow_missing=False, runtime_qualified=False, device_operations=False,
                  records=records)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()
