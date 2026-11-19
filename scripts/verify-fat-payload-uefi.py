#!/usr/bin/env python3
"""Build/run the actual FAT transport adapter in an AAVMF guest; no handset operations."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import zlib

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--composite', required=True, type=Path)
    parser.add_argument('--payload', required=True, type=Path)
    parser.add_argument('--edk', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--driver', type=Path, help='Use the exact driver produced by the Sony FD build')
    parser.add_argument('--cpu', default='cortex-a72')
    parser.add_argument('--memory-mib', type=int, default=1024)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    work = out / 'work'
    probe = work / 'FatPayload'
    probe.mkdir(parents=True)
    for name in ('FatPayloadProbe.c', 'FatPayloadProbe.inf'):
        shutil.copyfile(DEVICE / 'tests/qemu/FatPayload' / name, probe / name)
    kernel = (args.payload / 'kernel.macho').read_bytes()
    (probe / 'ExpectedPayload.h').write_text(f'#define EXPECTED_KERNEL_BYTES {len(kernel)}\n'
                                            f'#define EXPECTED_KERNEL_CRC 0x{zlib.crc32(kernel):08x}U\n')
    sony = PROJECT / 'ports/uefi-pdx234/Platforms/Sony/pdx234Pkg'
    for relative in ('Pdx234Payload.dec', 'Include/PdxBootSource.h', 'Drivers/PdxConfigFsDxe/PdxConfigFs.c',
                     'Drivers/PdxConfigFsDxe/PdxConfigFsDxe.inf'):
        target = work / 'pdx234Pkg' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sony / relative, target)
    mainline = PROJECT / 'sources/UniXNU-main-20261109'
    shutil.copytree(mainline / 'package/UniXNUPkg/Driver/UniXNURamDiskDxe', work / 'UniXNURamDiskDxe')
    # BEFORE is a firmware dispatcher order contract. LoadImage/StartImage invokes the same
    # compiled entry manually in this app fixture, so its DEPEX does not order this test.
    dsc = (DEVICE / 'tests/qemu/AndroidLinux/ConfigFsProbe.dsc').read_text()
    dsc = dsc.replace('PdxQemuConfigFs', 'PdxFatPayload')
    dsc = dsc[:dsc.index('[Components]')]
    dsc = dsc.replace('[LibraryClasses]', '[LibraryClasses]\n  ExtractGuidedSectionLib|MdePkg/Library/DxeExtractGuidedSectionLib/DxeExtractGuidedSectionLib.inf')
    dsc += '''[Components]
  FatPayload/FatPayloadProbe.inf
  pdx234Pkg/Drivers/PdxConfigFsDxe/PdxConfigFsDxe.inf {
    <LibraryClasses>
      NULL|MdeModulePkg/Library/LzmaCustomDecompressLib/LzmaCustomDecompressLib.inf
  }
  UniXNURamDiskDxe/UniXNURamDiskDxe.inf
'''
    (probe / 'FatPayloadProbe.dsc').write_text(dsc)
    conf = work / 'Conf'
    conf.mkdir()
    for name in ('target', 'tools_def', 'build_rule'):
        shutil.copyfile(args.edk / f'BaseTools/Conf/{name}.template', conf / f'{name}.txt')
    env = dict(os.environ, WORKSPACE=str(work), PACKAGES_PATH=f'{work}:{args.edk}',
               EDK_TOOLS_PATH=str(args.edk / 'BaseTools'), CONF_PATH=str(conf),
               CLANG_BIN='/usr/bin/', PYTHON_COMMAND='python3', PYTHONDONTWRITEBYTECODE='1',
               TMPDIR=str(out))
    env['PATH'] = ':'.join(['/root/unixnu-build/mu-venv/bin', str(args.edk / 'BaseTools/BinWrappers/PosixLike'),
                           str(args.edk / 'BaseTools/Source/C/bin'), env['PATH']])
    command = ['build', '-p', 'FatPayload/FatPayloadProbe.dsc', '-a', 'AARCH64', '-b', 'DEBUG', '-t', 'CLANGPDB', '-n8']
    with (out / 'build.log').open('w') as log:
        done = subprocess.run(command, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT)
    if done.returncode:
        raise RuntimeError((out / 'build.log').read_text()[-7000:])
    esp = out / 'esp'
    (esp / 'EFI/BOOT').mkdir(parents=True)
    (esp / 'EFI/Drivers').mkdir(parents=True)
    built = work / 'Build/PdxFatPayload/DEBUG_CLANGPDB/AARCH64'
    shutil.copyfile(built / 'FatPayloadProbe.efi', esp / 'EFI/BOOT/BOOTAA64.EFI')
    for name in ('PdxConfigFsDxe', 'UniXNURamDiskDxe'):
        shutil.copyfile(built / f'{name}.efi', esp / f'EFI/Drivers/{name}.efi')
    if args.driver:
        shutil.copyfile(args.driver, esp / 'EFI/Drivers/PdxConfigFsDxe.efi')
    shutil.copyfile(args.composite, esp / 'combo.Image')
    runner_source = PROJECT / 'references/xperia-mainline-20261107/package/Scripts/qemu-run.py'
    runner = out / 'qemu-run.py'
    text = runner_source.read_text()
    old = 'qemu, "-M", "virt", "-cpu", "cortex-a72",'
    if text.count(old) != 1:
        raise ValueError('Shared runner CPU command changed')
    text = text.replace(old, f'qemu, "-M", "virt", "-cpu", {args.cpu!r},')
    if args.memory_mib < 1024 or args.memory_mib > 8192:
        raise ValueError('Fixture memory must be 1024..8192 MiB')
    text = text.replace('"-m", "1024"', f'"-m", "{args.memory_mib}"')
    runner.write_text(text)
    command = ['python3', '-B', str(runner), str(esp), '--cpus', '1', '--timeout', '180',
               '--log', str(out / 'guest.log'), '--expect', 'FAT-PAYLOAD: PASS',
               '--reject', 'FAT-PAYLOAD: FAIL', '--reject', 'ASSERT', '--reject', 'Synchronous Exception']
    with (out / 'run.log').open('w') as log:
        done = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    print((out / 'run.log').read_text())
    (out / 'report.json').write_text(json.dumps(dict(command=command, exit_code=done.returncode,
        actual_sony_adapter_executed=done.returncode == 0, actual_shared_fat_path=done.returncode == 0,
        handset_tested=False, xnu_executed=False), indent=2)+'\n')
    raise SystemExit(done.returncode)


if __name__ == '__main__':
    main()
