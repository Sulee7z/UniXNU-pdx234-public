#!/usr/bin/env python3
"""Recompile the audited verified QEMU transport with a bounded read deadline."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

DEVICE = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    old = DEVICE/'out/d27-qemu-verified-block-002'
    text = (old/'NativeVirtioBlock.cpp').read_text()
    marker = '  clock_interval_to_deadline(1000, kMillisecondScale, &deadline);'
    begin = text.index('IOReturn NativeVirtioBlock::readRawSectors(')
    position = text.index(marker, begin)
    text = text[:position]+text[position:].replace(marker,
        '  // QEMU TCG/host file I/O may exceed one second during signed cache preflight.\n'
        '  // Keep a finite deadline and all existing reset/refusal checks.\n'
        '  clock_interval_to_deadline(30000, kMillisecondScale, &deadline);', 1)
    source = out/'NativeVirtioBlock.cpp'
    source.write_text(text)
    command = json.loads((old/'NativeVirtioBlock.command.json').read_text())
    command[command.index(str(old/'NativeVirtioBlock.cpp'))] = str(source)
    command[command.index('-o')+1] = str(out/'NativeVirtioBlock.o')
    for flag in ('-MF','-MJ'):
        if flag in command:
            command[command.index(flag)+1] = str(out/('NativeVirtioBlock.d' if flag=='-MF' else 'compile-record.json'))
    (out/'NativeVirtioBlock.command.json').write_text(json.dumps(command,indent=2)+'\n')
    with (out/'compile.log').open('w') as log:
        done = subprocess.run(command,
            cwd='/root/unixnu-build/pdx234-strict5-native-001/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT',
            stdout=log,stderr=subprocess.STDOUT)
    if done.returncode:
        raise RuntimeError((out/'compile.log').read_text()[-6000:])
    late = out/'NativeVirtioBlock.late.o'
    subprocess.run(['/root/unixnu-build/pdx234-pac-clang-build/bin/llvm-objcopy',
        '--remove-section=__DATA,__mod_init_func','--globalize-symbol=__GLOBAL__sub_I_NativeVirtioBlock.cpp',
        str(out/'NativeVirtioBlock.o'),str(late)],check=True)
    report = json.loads((old/'report.json').read_text())
    for name in ('IOBlockStorageDevice.late.o','SourceRootPolicies.o','verified_root.o','xnu_crypto.o','RootAnchor.o',
                 'interface-audit.json','root-policies.bin'):
        (out/name).symlink_to(old/name)
    for row in report['sources']:
        if row['source'].endswith('/NativeVirtioBlock.cpp'):
            row.update(source=str(source),source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                       object_sha256=hashlib.sha256(late.read_bytes()).hexdigest())
    report.update(read_timeout_ms=30000,reset_timeout_ms=1000,
                  source_receipt='out/d27-qemu-verified-block-002/report.json',
                  actual_io_qualified=False,kernel_linked=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(read_timeout_ms=30000,device_operations=False,compiled=True),indent=2))


if __name__ == '__main__':
    main()
