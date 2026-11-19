#!/usr/bin/env python3
"""Replace only the XNU copy in a verified FAT payload with the official entry probe."""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import shutil
import struct
import subprocess
import zlib

SOURCE_SHA = '098469d880049ad9f1811c3e893874fa56cba72957200fcb4dad756627af0efe'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, type=Path)
    parser.add_argument('--diagnostic', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--label', default='002', choices=('002', '003', '004'))
    args = parser.parse_args()
    report = json.loads((args.base / 'report.json').read_text())
    probe = json.loads(args.diagnostic.with_suffix('.entry-probe.json').read_text())
    seal = json.loads(args.diagnostic.with_name(args.diagnostic.name + '.crypto-hmac.json').read_text())
    kernel = args.diagnostic.read_bytes()
    if report['kernel_sha256'] != SOURCE_SHA or digest((args.base/'kernel.macho').read_bytes()) != SOURCE_SHA:
        raise ValueError('Pristine strict payload identity changed')
    reset = (probe.get('no_reset') is False and probe.get('reset_checkpoint') == 'post-MMU' and
              probe.get('reset_delay') == 6 and probe.get('timebase_hz') == 19200000)
    call_reset = (probe.get('no_reset') is False and
                  probe.get('reset_checkpoint') == 'after _arm_vm_init in _arm_init' and
                  probe.get('reset_after') == '_arm_vm_init' and probe.get('reset_delay') == 6 and
                  probe.get('timebase_hz') == 19200000)
    if (probe['source_kernel_sha256'] != SOURCE_SHA or probe['panic_screen'] or
            not (probe.get('no_reset') is True or reset or call_reset)):
        raise ValueError('Require a supported official probe')
    if args.label != ('004' if call_reset else '003' if reset else '002'):
        raise ValueError('Diagnostic label must match the probe reset behavior')
    if seal['kernel_sha256'] != digest(kernel):
        raise ValueError('Diagnostic copy was not sealed after the entry probes')
    args.out.mkdir(parents=True, exist_ok=False)
    for name in ('Android.original.Image', 'kernel.macho.adt', 'platform-seed'):
        shutil.copyfile(args.base/name, args.out/name)
    (args.out/'kernel.macho').write_bytes(kernel)
    shutil.copyfile(args.diagnostic.with_suffix('.entry-probe.json'), args.out/'kernel.macho.entry-probe.json')
    shutil.copyfile(args.diagnostic.with_name(args.diagnostic.name+'.crypto-hmac.json'), args.out/'kernel.macho.crypto-hmac.json')
    image=args.out/'payload.fat';shutil.copyfile(args.base/'payload.fat',image)
    subprocess.run(['mcopy','-o','-i',str(image),str(args.out/'kernel.macho'),
                    '::/EFI/UniXNU/Payloads/kernel.macho'],check=True)
    config=args.out/'unixnu.toml'
    subprocess.run(['mcopy','-i',str(image),'::/EFI/UniXNU/unixnu.toml',str(config)],check=True)
    title = ('D27 XNU - VM init return then reset' if call_reset else
             'D27 XNU - MMU then reset in 6s' if reset else 'D27 XNU - blue-magenta diagnosis')
    text=config.read_text().replace('Sony PDX234 XNU entry probe',f'PDX234 D27 ENTRY DIAG {args.label}').replace(
        'D27 strict XNU - entry test', title)
    if reset or call_reset:
        text=text.replace('Start the XNU entry test?',
                          'Reset 6 seconds after arm_vm_init returns. Start?' if call_reset else
                          'MMU diagnostic: reset 6 seconds after MMU enable. Start?')
    config.write_text(text)
    subprocess.run(['mcopy','-o','-i',str(image),str(config),'::/EFI/UniXNU/unixnu.toml'],check=True)
    readback=args.out/'kernel-roundtrip'
    subprocess.run(['mcopy','-i',str(image),'::/EFI/UniXNU/Payloads/kernel.macho',str(readback)],check=True)
    if readback.read_bytes()!=kernel:
        raise ValueError('FAT diagnostic kernel roundtrip failed')
    readback.unlink()
    raw=image.read_bytes();compressed=bytearray(lzma.compress(raw,format=lzma.FORMAT_ALONE,preset=6))
    compressed[5:13]=struct.pack('<Q',len(raw))
    if lzma.decompress(compressed,format=lzma.FORMAT_ALONE)!=raw:
        raise ValueError('LZMA roundtrip failed')
    bundle=struct.pack('<8s4IQ',b'PDXFAT02',32,len(compressed),len(raw),zlib.crc32(raw),0)+compressed
    (args.out/'payload.bundle').write_bytes(bundle)
    report.update(source_kernel_sha256=SOURCE_SHA,kernel_sha256=digest(kernel),
                  entry_probe=probe,crypto_seal=seal,payload_sha256=digest(raw),payload_bytes=len(raw),
                  bundle_sha256=digest(bundle),bundle_bytes=len(bundle),
                   note=('Same Sony DRAM subset and FD as candidate001; official entry probe; '
                          + ('PSCI reset six seconds after arm_vm_init returns.' if call_reset else
                             'PSCI reset six seconds after post-MMU checkpoint.' if reset else 'no reset.')))
    (args.out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
