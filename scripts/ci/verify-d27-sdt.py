#!/usr/bin/env python3
"""Read SDT targets and names from the actual prelinked readonly kernel section."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.strict / 'XnuPrelink'))
    from kc_image import Image
    raw = (args.strict / 'kernel.macho').read_bytes()
    result = json.loads((args.strict / 'result.json').read_text())
    digest = hashlib.sha256(raw).hexdigest()
    if digest != result['candidate_sha256']:
        raise ValueError('Strict kernel identity changed')
    root = Image(raw)
    member = Image(raw, root.entries['com.apple.kernel'][1])
    fixups = root.fixups()
    section = next(s for s in member.sections if s['name'] == '__sdt')
    if section['segment'] != '__TEXT' or not section['size'] or section['size'] % 24:
        raise ValueError('Unexpected SDT layout')
    segment = next(s for s in root.segments if s['va'] <= section['va'] and
                   section['va'] + section['size'] <= s['va'] + s['size'])
    protections = struct.unpack_from('<II', raw, segment['command_offset'] + 56)
    if protections != (1, 1):
        raise ValueError('SDT root mapping must be read-only and non-executable')

    def string(address):
        sec = member.section(address)
        if not sec or sec['name'] not in ('__sdt_cstring', '__cstring'):
            raise ValueError('SDT name outside string section')
        offset = member.offset(address)
        end = raw.index(b'\0', offset, offset + min(4096, sec['va'] + sec['size'] - address))
        return raw[offset:end].decode('ascii')

    records = []
    for offset in range(0, section['size'], 24):
        values = []
        for word in range(3):
            site = section['va'] + offset + word * 8
            values.append(fixups[site][0] if site in fixups else struct.unpack('<Q', member.read(site, 8))[0])
        site, provider, name = values
        code = member.section(site)
        if not code or code['segment'] != '__TEXT_EXEC':
            raise ValueError('SDT target outside kernel executable segment')
        records.append(dict(site=hex(site), provider=string(provider), name=string(name)))
    mac = sum(r['name'].startswith('mac__') for r in records)
    if not mac:
        raise ValueError('Restored MAC SDT records absent')
    report = dict(kernel_sha256=digest, records=len(records), mac_records=mac,
                  readonly_protection=list(protections), runtime_verified=False)
    with args.out.open('x') as stream:
        json.dump(dict(summary=report, records=records), stream, indent=2)
        stream.write('\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
