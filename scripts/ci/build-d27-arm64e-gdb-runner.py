#!/usr/bin/env python3
"""Copy the pinned read-only GDB observer and qualify D27 arm64e saved state."""
import argparse
import hashlib
import json
from pathlib import Path
import re

DEVICE = Path(__file__).resolve().parents[2]
SOURCE = DEVICE.parents[1]/'sources/UniXNU-main-20261109/scripts/qemu-entry/gdb-stop.py'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    text=SOURCE.read_text()
    old_size="raw = packet(f'm{current[0]:x},128')"
    old_header="if struct.unpack_from('<2I', state) != (21, 72):"
    old_length="if len(raw) != 592 or raw.startswith('E'):"
    if text.count(old_size)!=1 or text.count(old_header)!=1 or text.count(old_length)!=1:
        raise ValueError('Pinned runner ABI sites changed; inspect before adapting')
    text=text.replace(old_size,"raw = packet(f'm{current[0]:x},130')")
    text=text.replace(old_length,"if len(raw) != 608 or raw.startswith('E'):")
    # arm_saved_state64 is 296 bytes with jophash; ash is another 8 bytes.
    # ARM_SAVED_STATE64_COUNT counts the state only, not the outer header.
    text=text.replace(old_header,"if struct.unpack_from('<2I', state) != (21, 74):")
    for before, after in [
        ("if struct.unpack_from('<2I', saved) != (21, 72):",
         "if struct.unpack_from('<2I', saved) != (21, 74):"),
        ("if struct.unpack_from('<2I', raw_state) == (21, 72):",
         "if struct.unpack_from('<2I', raw_state) == (21, 74):"),
        ("state_pointers=[(f'x{index}',values[index]) for index in range(19,29)]",
         "state_pointers=[('x0',values[0])]+[(f'x{index}',values[index]) for index in range(19,29)]")]:
        if text.count(before)!=1:
            raise ValueError('Pinned saved-state observer site changed: '+before)
        text=text.replace(before,after)
    text=text.replace('Unexpected saved-state ABI for pinned Darwin 23 ARM64',
                      'Unexpected saved-state ABI for D27 arm64e')
    # Keep the pinned packet/QMP helpers available from a local runner copy.
    anchor='parser = argparse.ArgumentParser(description=__doc__)'
    if text.count(anchor)!=1:
        raise ValueError('Pinned runner parser site changed')
    text=text.replace(anchor,'import sys\nsys.path.insert(0, '+repr(str(SOURCE.parent))+')\n\n'+anchor)
    helpers=DEVICE/'ci/qemu'
    text=text.replace(anchor,'sys.path.insert(0, '+repr(str(helpers))+')\n'
                      'from d27_user_memory import read_user_memory, kernel_pointer_view\n\n'+anchor)
    before="            if args.inspect_entry_user_state and values[32] == args.address and not interrupted:\n"
    if text.count(before)!=1:
        raise ValueError('Pinned user-state capture site changed')
    mmu='''                user_mmu = {}
                user_target = feature('target.xml')
                for include in user_target.findall('{http://www.w3.org/2001/XInclude}include'):
                    document = feature(include.attrib['href'])
                    for register in document.findall('reg'):
                        if register.attrib['name'] in ('TCR_EL1', 'TTBR0_EL1'):
                            word = packet(f'p{int(register.attrib["regnum"]):x}')
                            user_mmu[register.attrib['name']] = int.from_bytes(bytes.fromhex(word), 'little')
                report['user_memory_translation_registers'] = {key: hex(value) for key,value in user_mmu.items()}
'''
    text=text.replace(before,before+mmu)
    before="                    if current.get('user_state'):state_pointers.append(('current-thread.upcb',int(current['user_state'],16)))"
    after='''                    if current.get('user_state'):
                        raw_pointer = int(current['user_state'],16)
                        state_pointers.append(('current-thread.upcb', raw_pointer))
                        state_pointers.append(('current-thread.upcb.kernel-address-view',
                            kernel_pointer_view(raw_pointer, user_mmu['TCR_EL1'])))'''
    if text.count(before)!=1:
        raise ValueError('Pinned current-thread state site changed')
    text=text.replace(before,after)
    before="                    candidate['register_memory']={}"
    after='''                    try:
                        candidate['instruction_memory_physical'] = read_user_memory(packet, user_mmu, regs[32], 64)
                    except (ValueError, RuntimeError) as error:
                        candidate['instruction_memory_physical'] = {'error': str(error)}
                    candidate['register_memory']={}'''
    if text.count(before)!=1:
        raise ValueError('Pinned saved instruction site changed')
    text=text.replace(before,after)
    before="                        candidate['register_memory'][request]=capture"
    after='''                        if len(capture['bytes'])//2 < length:
                            try:
                                capture['physical_fallback'] = read_user_memory(packet, user_mmu, address, length)
                            except (ValueError, RuntimeError) as error:
                                capture['physical_fallback'] = {'error': str(error)}
                        candidate['register_memory'][request]=capture'''
    if text.count(before)!=1:
        raise ValueError('Pinned saved-register memory site changed')
    text=text.replace(before,after)
    path=args.out/'gdb-stop-d27-arm64e.py';path.write_text(text)
    record=dict(source=str(SOURCE),source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        runner_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),saved_state_flavor=21,
        saved_state_words=74,saved_state_bytes=304,user_register_offsets_unchanged=True,
        user_memory_helper_sha256=hashlib.sha256((helpers/'d27_user_memory.py').read_bytes()).hexdigest(),
        user_translation_reads_only=True,
        applies_only_to_local_QEMU_observer=True,device_operations=False)
    (args.out/'runner.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
