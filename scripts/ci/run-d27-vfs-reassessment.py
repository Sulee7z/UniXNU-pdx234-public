#!/usr/bin/env python3
"""Observe a retained D27 VirtIO kernel through reboot/panic, read-only disks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--os-disk', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    policy = json.loads((DEVICE / 'out/d27-owner-policies-001/report.json').read_text())
    disks = {'OS': args.os_disk, 'SystemOS': Path(policy['policies'][1]['image'])}
    for entry in policy['policies']:
        path = disks[entry['component']]
        if path.stat().st_size != entry['verification']['image_bytes'] or sha(path) != entry['verification']['image_sha256']:
            raise ValueError('Original D27 disk identity mismatch: ' + str(path))
    strict = Path('/root/unixnu-build/pdx234-qemu-storage-001/strict-official-stack-001/final')
    report = json.loads((strict / 'kernel.json').read_text())
    if report['missing'] or report['stubbed'] or report['allow_missing'] or sha(strict / 'kernel.macho') != report['candidate_sha256']:
        raise ValueError('Retained QEMU kernel failed strict identity checks')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    fixture = DEVICE / 'out/qemu-d27-strict-sanitizer-sigabrt-001'
    shutil.copytree(fixture / 'esp', out / 'esp')
    kernel = out / 'esp/EFI/UniXNU/Payloads/kernel.macho'
    shutil.copyfile(strict / 'kernel.macho', kernel)
    sys.path.insert(0, str(BASE / 'strict-pac-abi-013/XnuPrelink'))
    from kc_image import Image
    image = Image(kernel.read_bytes())
    member = Image(image.data, image.entries['com.apple.kernel'][1])
    names = {name: address for address, symbols in member.symbols().items() for name in symbols}
    runner = DEVICE / 'out/d27-arm64e-observer-007/gdb-stop-d27-arm64e.py'
    # Observer commands do not patch guest code, registers, pointers or counts.
    command = ['python3', '-B', str(runner), hex(names['_reboot']),
               '--esp', str(out / 'esp'), '--kernel', str(kernel),
               '--fixture', str(out / 'observation'), '--gic-version', '3',
               '--qemu-memory-mib', '4096', '--system-registers', '--qemu-ramfb',
               '--firmware', '/usr/share/AAVMF/AAVMF_CODE.fd', '--timeout', str(args.timeout),
               '--virtio-block-image', str(disks['OS']),
               '--virtio-extra-block-image', str(disks['SystemOS']), '--capture-screen',
               '--process-layout-plan', str(DEVICE / 'out/d27-process-layout-001/process-plan-with-upcb.json'),
               '--allproc-address', hex(names['_allproc']), '--proc-pid-offset', '96',
               '--proc-comm-offset', '1492', '--read-frame-locals',
               '--syscall-start-address', hex(names['_load_init_program_at_path']),
               '--syscall-log-address', hex(names['_unix_syscall'])]
    for number in (1, 4, 37, 55, 328, 381, 397, 520, 521, 529):
        command += ['--syscall-number', str(number)]
    for name in ('_panic', '_panic_with_options', '_Assert', '_unixnu_fileset_unmapped'):
        command += ['--also-stop', hex(names[name])]
    for name in ('_native_owner_data_status', '_native_owner_data_stage',
                 '_native_owner_cache_status', '_native_owner_cache_stage',
                 '_native_virtio_integrity_failures', '_native_virtio_read_failures'):
        if name in names:
            command += ['--read-memory', f'{names[name]:x}:4']
    inputs = dict(command=command, kernel_sha256=sha(kernel),
                  kernel_source=str(strict), current_handset_kernel=False,
                  purpose='Retained VirtIO software baseline: observe launchd reboot or first panic',
                  disk_sha256={name: entry['verification']['image_sha256']
                               for name in disks for entry in policy['policies'] if entry['component'] == name},
                  device_operations=False)
    (out / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    print('QEMU observer running:', out, flush=True)
    with (out / 'run.log').open('x') as log:
        done = subprocess.run(command, env=dict(os.environ, TMPDIR=str(out), PYTHONDONTWRITEBYTECODE='1'),
                              stdout=log, stderr=subprocess.STDOUT)
    stop = out / 'observation/gdb-stop.json'
    observed = json.loads(stop.read_text()) if stop.exists() else {}
    result = dict(exit_code=done.returncode, pc=observed.get('pc'),
                  reached_reboot=observed.get('pc') == hex(names['_reboot']),
                  bounded_timeout_interrupted=observed.get('bounded_timeout_interrupted'),
                  actual_process=observed.get('actual_process'), argument_memory=observed.get('argument_memory'),
                  current_handset_kernel=False, hardware_verified=False, device_operations=False)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)
    raise SystemExit(done.returncode)


if __name__ == '__main__':
    main()
