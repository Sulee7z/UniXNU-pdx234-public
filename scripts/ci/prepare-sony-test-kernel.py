#!/usr/bin/env python3
"""Install official entry bars and branch panic to the normally linked renderer."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

DEVICE = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--mainline', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    original = args.kernel.read_bytes()
    report = json.loads(args.report.read_text())
    digest = hashlib.sha256(original).hexdigest()
    if (report['candidate_sha256'] != digest or report['missing'] or report['stubbed'] or
            report['allow_missing'] or not report['candidate_written']):
        raise ValueError('Require complete strict kernel identity')
    args.out.mkdir(parents=True, exist_ok=False)
    kernel = args.out / 'kernel.macho'
    kernel.write_bytes(original)
    adapter = load('sony_probe_symbols', DEVICE / 'scripts/ci/install-d27-entry-probe.py')
    probe = load('sony_official_probe', args.mainline / 'scripts/patch-xnu-entry-probe.py')
    probe.kernel_symbols = adapter.native_symbols
    sys.argv = ['patch-xnu-entry-probe.py', str(kernel), '--no-reset']
    probe.main()
    sys.path.insert(0, str(DEVICE / 'ci/XnuPrelink'))
    from kc_image import Image
    data = bytearray(kernel.read_bytes())
    collection = Image(data)
    native = Image(data, collection.entries['com.apple.kernel'][1])
    names = {name: address for address, symbols in native.symbols().items() for name in symbols}
    hooks = []
    for name, target in (('_panic', '_panic_screen'), ('_panic_trap_to_debugger', '_panic_screen_common')):
        address, destination = names[name], names[target]
        old = native.read(address, 4)
        if struct.unpack('<I', old)[0] not in (0xd503237f, 0xd503245f, 0xd503233f):
            raise ValueError('Unexpected panic entry instruction: ' + name)
        offset = next(s['fileoff'] + address - s['va'] for s in native.segments
                      if s['va'] <= address <= s['va'] + s['filesize'] - 4)
        delta = destination - address
        if delta % 4 or not -(1 << 27) <= delta < 1 << 27:
            raise ValueError('Panic renderer branch out of range')
        struct.pack_into('<I', data, offset, 0x14000000 | ((delta >> 2) & 0x3ffffff))
        hooks.append(dict(symbol=name, address=hex(address), target=target,
                          destination=hex(destination), original=old.hex()))
    kernel.write_bytes(data)
    record = dict(source_kernel_sha256=digest, patched_kernel_sha256=hashlib.sha256(data).hexdigest(),
                  strict_report=str(args.report), entry_bars=True, no_reset=True,
                  panic_renderer='Official source linked normally; Darwin ARM64 stack/va_list entries',
                  hooks=hooks, kernel_crypto_reseal_required=True, device_operations=False)
    (args.out / 'diagnostic.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
