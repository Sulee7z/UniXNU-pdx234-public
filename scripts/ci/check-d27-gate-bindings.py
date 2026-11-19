#!/usr/bin/env python3
"""Refuse the observed public/internal gate ABI misbinding in a strict image."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

DEVICE = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(DEVICE/'ci/XnuPrelink'))
    from kc_image import Image
    raw = (args.strict/'kernel.macho').read_bytes()
    strict = json.loads((args.strict/'kernel.json').read_text())
    mapping = json.loads((args.strict/'kernel.map.json').read_text())
    if (hashlib.sha256(raw).hexdigest()!=strict['candidate_sha256'] or strict['missing'] or
            strict['stubbed'] or strict['allow_missing']):
        raise ValueError('Strict image identity differs')
    original = (DEVICE/'.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed').read_bytes()
    old, image = Image(original), Image(raw)
    rows = []
    for address, name in [('0xfffffff00a1f2674','_lck_rw_gate_close'),
                          ('0xfffffff00a1f2540','_lck_rw_gate_try_close')]:
        entry = mapping['functions'][address]
        if entry['name'] != name or entry['how'] != 'reviewed':
            raise ValueError('Public gate API must use its reviewed two-argument wrapper')
        rows.append(dict(original=address,native_symbol=name,how=entry['how']))
    # The APFS call still passes lock x0 and gate x1; its code is not patched.
    address = 0xfffffff00a03719c
    if image.read(address,12)!=old.read(address,12):
        raise ValueError('Original APFS gate caller changed')
    args.out.write_text(json.dumps(dict(kernel_sha256=strict['candidate_sha256'],bindings=rows,
        original_apfs_caller_preserved=True,passed=True,device_operations=False),indent=2)+'\n')
    print('PASS: exact public gate close/try-close mappings; original APFS caller preserved')


if __name__ == '__main__':
    main()
