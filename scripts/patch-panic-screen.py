#!/usr/bin/env python3
"""Apply the official panic screen to the payload's kernel copy.

llvm-nm cannot read the prelinked fileset container, so the reviewed Sony
adapter's native nlist reader replaces the official symbol lookup. The probe
itself is the unchanged upstream script.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

PORT = Path('/mnt/g/UniXNU-Port/ports/UniXNU-pdx234')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path, help='the COPY of the kernel to patch in place')
    parser.add_argument('--mainline', required=True, type=Path)
    parser.add_argument('--uefi', required=True, type=Path, help='Mu-Silicium checkout with the panic screen font')
    parser.add_argument('--preserve-auth', action='store_true', help='Keep PACIBSP at both panic entries; hook the following instruction')
    args = parser.parse_args()
    adapter = load('sony_probe_adapter', PORT / 'scripts/ci/install-d27-entry-probe.py')
    script = args.mainline / 'scripts/patch-xnu-entry-probe.py'
    probe = load('official_entry_probe', script)
    original = args.kernel.read_bytes()
    symbols = adapter.native_symbols(args.kernel)
    probe.kernel_symbols = adapter.native_symbols
    hooks = []
    padding = {}
    if args.preserve_auth:
        original_rebase = probe.rebase

        def authenticated_rebase(kernel, data):
            names = original_rebase(kernel, data)
            # The live diagnostic renderer adds code to the upstream panic
            # screen. Use the assembly-aligned gap before ExceptionVectorsBase
            # when it exists, with an explicit zero-byte/symbol boundary guard.
            if '_boot_progress_panic_text' in names:
                end = names['_ExceptionVectorsBase']
                begin = end - 0xe00
                if (end & 0xfff or any(begin <= address < end for address in names.values()) or
                        any(data[probe.file_offset(begin):probe.file_offset(end)])):
                    # Recompiling Blocks producers can consume the old vector
                    # alignment gap. Use ONLY file-backed __TEXT_EXEC padding
                    # after every native section; never a guessed in-function
                    # zero run or the reclaimable __KLD segment.
                    sys.path.insert(0,str(PORT/'ci/XnuPrelink'))
                    from kc_image import Image
                    collection=Image(data)
                    member=Image(data,collection.entries['com.apple.kernel'][1])
                    segment=next(s for s in member.segments if s['name']=='__TEXT_EXEC')
                    section_end=max(s['va']+s['size'] for s in member.sections if s['segment']=='__TEXT_EXEC')
                    begin=(section_end+15)&~15
                    end=segment['va']+min(segment['size'],segment['filesize'])
                    reserves=[s for s in member.sections if s['segment']=='__TEXT_EXEC' and s['name']=='__pdxpanic']
                    if end-begin<0xe00:
                        if len(reserves)!=1 or reserves[0]['size']!=4096:
                            raise ValueError('No sufficient non-reclaimable executable padding or dedicated reserve')
                        reserve=reserves[0];begin=reserve['va'];end=begin+reserve['size']
                        if begin&15:raise ValueError('Dedicated panic reserve lacks16-byte entry alignment')
                        if begin<segment['va'] or end>segment['va']+min(segment['size'],segment['filesize']):
                            raise ValueError('Dedicated panic reserve lies outside file-backed executable memory')
                        if any(s is not reserve and s['segment']=='__TEXT_EXEC' and
                               s['va']<end and begin<s['va']+s['size'] for s in member.sections):
                            raise ValueError('Dedicated panic reserve overlaps another section')
                        if any(member.read(begin,end-begin)):raise ValueError('Dedicated panic reserve is not zero')
                        padding.update(kind='native-__TEXT_EXEC-reserved-section',section='__pdxpanic',reserved_bytes=reserve['size'])
                    end=begin+0xe00
                    sites=set(member.symbols())|set(member.function_starts())|set(collection.fixups())
                    sites.update(value[0] for value in collection.fixups().values())
                    if any(begin<=at<end for at in sites) or any(member.read(begin,end-begin)):
                        raise ValueError('Executable segment padding is occupied or referenced')
                    if probe.file_offset(begin)!=member.offset(begin) or probe.file_offset(end-1)!=member.offset(end-1):
                        raise ValueError('Padding file mapping differs from the native executable segment')
                    if not padding:padding['kind']='native-__TEXT_EXEC-tail'
                    padding.update(section_end=hex(section_end),
                                    segment_end=hex(segment['va']+segment['filesize']))
                else:
                    padding.update(kind='exception-vector-alignment')
                padding.update(begin=hex(begin),end=hex(end),bytes=end-begin,original_bytes_zero=True)
                probe.CAVES = {stage: begin + (stage-1)*probe.CAVE_SIZE for stage in (1,2,3,4)}
                probe.PANIC_CAVE_END = end
            for name in ('_panic', '_panic_trap_to_debugger'):
                address = names[name]
                at = probe.file_offset(address)
                if struct.unpack_from('<I', data, at)[0] != 0xD503237F:
                    raise ValueError('Expected native PACIBSP at ' + name)
                following = struct.unpack_from('<I', data, at + 4)[0]
                if following & 0xFFC003FF != 0xD10003FF:
                    raise ValueError('Expected stack allocation after PACIBSP at ' + name)
                hooks.append(dict(symbol=name, entry=hex(address), hook=hex(address + 4),
                                  preserved_instruction='PACIBSP', replaced_instruction=hex(following)))
                names[name] = address + 4
            probe.PANIC_VA = names['_panic']
            return names

        probe.rebase = authenticated_rebase
    # The upstream probe reserves 0x60 bytes per probe cave and starts the panic
    # screen after the last cave. The blue and magenta bar code is shorter than
    # that, so the shared padding can start 0x10 bytes earlier: the panic screen
    # then fits in the free padding with 9 bytes to spare.
    probe.CAVE_SIZE = 0x50
    os.environ['UNIXNU_UEFI'] = str(args.uefi)
    sys.argv = [str(script), str(args.kernel), '--panic-screen', '--no-reset']
    probe.main()
    patched = args.kernel.read_bytes()
    if args.preserve_auth:
        sites = [probe.ENTRY_VA, probe.MMU_ENABLE_VA, *[int(hook['hook'], 16) for hook in hooks]]
        offsets = {probe.file_offset(address) + byte for address in sites for byte in range(4)}
        low, high = probe.file_offset(min(probe.CAVES.values())), probe.file_offset(probe.PANIC_CAVE_END)
        changed = {i for i, (a, b) in enumerate(zip(original, patched)) if a != b}
        if len(original) != len(patched) or any(i not in offsets and not (low <= i < high and original[i] == 0) for i in changed):
            args.kernel.write_bytes(original)
            raise ValueError('Diagnostic patch changed bytes outside the four non-auth hooks and empty padding')
        for hook in hooks:
            at = probe.file_offset(int(hook['entry'], 16))
            if patched[at:at + 4] != original[at:at + 4]:
                args.kernel.write_bytes(original)
                raise ValueError('PACIBSP was modified')
    report = dict(source_kernel_sha256=hashlib.sha256(original).hexdigest(),
                  patched_kernel_sha256=hashlib.sha256(patched).hexdigest(),
                  official_probe=str(script),
                  official_probe_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
                  fileset_symbol_adapter='native N_SECT only; no STAB or indirect symbols',
                  native_defined_symbol_addresses=len(symbols),
                   panic_screen=True, no_reset=True,
                    auth_instructions_preserved=bool(args.preserve_auth), panic_hooks=hooks,
                   diagnostic_padding=padding,
                  changed_bytes=sum(a != b for a, b in zip(original, patched)),
                  guest_executed=False)
    args.kernel.with_suffix('.panic-screen.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
