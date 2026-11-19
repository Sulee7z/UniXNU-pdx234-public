#!/usr/bin/env python3
"""Read/disassemble exact strict066 key setup, ABI, pager, and OS call bodies."""
import bisect
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from audit import BASE, HERE, STRICT_SHA, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=HERE / 'supplemental-code-003')
    args = parser.parse_args()
    strict = BASE / 'strict-sony-touch-066-002'
    if sha(strict / 'kernel.macho') != STRICT_SHA:
        raise ValueError('Exact066 strict kernel required')
    out = args.out.resolve()
    if not out.is_relative_to(HERE) or out == HERE:
        raise ValueError('Output must stay below assigned audit directory')
    out.mkdir(exist_ok=False)
    sys.path.insert(0, str(strict / 'XnuPrelink'))
    from kc_image import Image
    raw = (strict / 'kernel.macho').read_bytes()
    image = Image(raw)
    member = Image(raw, image.entries['com.apple.kernel'][1])
    names = {name: address for address, values in member.symbols().items() for name in values}
    starts = member.function_starts()
    requested = {'common_start': 512, '_Call_continuation': None,
                 '_source_corecrypto14_bootstrap': None, '_work_interval_ctl': None,
                 '_priv_check_cred': None, '_shared_region_pager_data_request': None,
                 '_dyld_pager_data_request': None, '_native_gpu_addon_write': None,
                 '_sys_dup3': None, '_pipe2': None, '_aio_readv': None, '_aio_writev': None,
                 '_fchflagsat': None, '_getumask': None, '_fsctlat': None,
                 '_guarded_ftruncate_np': None, '_proc_getcdhash_with_length': None,
                 '_image4_v2_interface_register': None, '_appsync_trust_user_code': None}
    record = {}
    for name, length in requested.items():
        if name not in names:
            raise ValueError('Requested linked implementation absent: ' + name)
        address = names[name]
        if length is None:
            length = starts[bisect.bisect_right(starts, address)] - address
        code = member.read(address, length)
        data = '\n'.join(' '.join(f'0x{b:02x}' for b in code[i:i + 4]) for i in range(0, len(code), 4))
        result = subprocess.run(['llvm-mc-23', '--disassemble', '--triple=aarch64', '--mattr=+v8.3a,+pauth,+lse'],
                                input=data, capture_output=True, text=True, check=True, timeout=30)
        lines = [s.strip() for s in result.stdout.splitlines() if s.strip() and s.strip() != '.text']
        if len(lines) != length // 4:
            raise ValueError('Decoder omitted instructions: ' + name)
        output = out / (name + '.asm')
        output.write_text('\n'.join(f'{address + i * 4:#x} {line}' for i, line in enumerate(lines)) + '\n')
        record[name] = {'address': hex(address), 'bytes': length, 'code_sha256': hashlib.sha256(code).hexdigest(),
                        'disassembly': str(output), 'disassembly_sha256': sha(output)}
        record[name]['text'] = '\n'.join(lines)
    setup = record['common_start']['text']
    for key in ('APIA', 'APIB', 'APDA', 'APDB', 'APGA'):
        for half in ('Lo', 'Hi'):
            if 'msr\t' + key + 'Key' + half + '_EL1' not in setup:
                raise ValueError('Architectural PAC key register write absent')
    if setup.index('msr\tAPGAKeyHi_EL1') > setup.index('msr\tSCTLR_EL1'):
        raise ValueError('Keys must be set before enabling SCTLR')
    continuation = record['_Call_continuation']['text']
    if 'mov\tx21, #54535' not in continuation or 'blraa\tx20, x21' not in continuation:
        raise ValueError('Continuation discriminator does not match generated063 ABI')
    kmod = record['_source_corecrypto14_bootstrap']['text']
    if 'mov\tx17, #58622' not in kmod or 'blraa\tx8, x17' not in kmod:
        raise ValueError('Original kmod type discrimination was lost')
    syscalls = {148: '_pipe2', 149: '_sys_dup3', 214: '_fchflagsat', 215: '_getumask',
                246: '_aio_readv', 247: '_aio_writev', 249: '_fsctlat', 352: '_guarded_ftruncate_np'}
    fixups = image.fixups()
    table = names['_sysent']
    syscall_rows = []
    for number, name in syscalls.items():
        slot = table + 24 * number  # target CONFIG_REQUIRES_U32_MUNGING struct sysent
        value = fixups.get(slot)
        if not value or value[0] != names[name] or value[1:4] != (1, 0, 0xbcad):
            raise ValueError('Actual Darwin26 syscall/PAC target mismatch: ' + name + ' ' + repr(value))
        syscall_rows.append({'number': number, 'symbol': name, 'slot': hex(slot), 'target': hex(value[0]),
                             'authenticated': True, 'key': 'IA', 'diversity': '0xbcad'})
    for row in record.values():
        del row['text']
    result = {'passed': True, 'strict_sha256': STRICT_SHA, 'implementations': record,
              'darwin26_syscall_slots': syscall_rows,
              'five_architectural_key_pairs_before_sctlr': True, 'continuation_discriminator': '0xd507',
              'kmod_discriminator': '0xe4fe', 'auth_removed': False,
              'limits': 'Symbol/code presence proves selection, not every function semantic or per-CPU runtime key contents.',
              'device_operations': False}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': True, 'out': str(out), 'functions': len(record)}))


if __name__ == '__main__':
    main()
