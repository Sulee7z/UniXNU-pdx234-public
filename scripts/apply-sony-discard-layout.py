#!/usr/bin/env python3
"""Fresh Sony discard-Data transaction. Never format raw encrypted userdata.

Writes only Data's first1MiB, the reviewed two GPT regions, and recovery RAM.
Root image installation is a separate stage and never touches boot partitions.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys

DEVICE = Path(__file__).resolve().parents[1]
SERIAL = 'PDX_DEVICE_SERIAL'
CONFIRM = SERIAL + ' DISCARD-DATA unixnu 68719476736'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', required=True)
    p.add_argument('--official-dual-sys', required=True, type=Path)
    p.add_argument('--refresh-helper', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--os-image', required=True, type=Path)
    p.add_argument('--systemos-image', required=True, type=Path)
    p.add_argument('--execute', action='store_true')
    p.add_argument('--confirm')
    args = p.parse_args()
    if args.execute and args.confirm != CONFIRM:
        p.error('Need exact discard-Data confirmation')
    args.out.mkdir(exist_ok=False, parents=True)
    adb = [args.adb, '-s', SERIAL]

    def read(command, binary=False):
        mode = ['exec-out'] if binary else ['shell', '-T']
        raw = subprocess.run([*adb, *mode, command], check=True,
                             capture_output=True, timeout=120).stdout
        return raw if binary else raw.replace(b'\r\n', b'\n')

    if subprocess.check_output([*adb, 'get-state'], timeout=20).strip() != b'recovery':
        raise ValueError('Need the existing authorized recovery')
    if subprocess.run([*adb, 'shell', '-T', 'exit 37'], capture_output=True, timeout=20).returncode != 37:
        raise ValueError('ADB does not preserve remote exit status')
    install = load('sony_install', DEVICE / 'ci/dual_sys/sony_install.py')
    manifest, image_plan = install.manifest()
    for window, image in zip(image_plan['windows'], [args.os_image, args.systemos_image]):
        if image.stat().st_size != window['bytes'] or digest(image) != window['sha256']:
            raise ValueError('Input image differs: ' + window['name'])
        window['host_image'] = str(image.resolve())
    (args.out / 'ios27-install-plan.json').write_text(json.dumps(image_plan, indent=2) + '\n')
    capture = args.out / 'capture'
    subprocess.run([sys.executable, '-B', str(DEVICE / 'scripts/capture-sony-recovery-gpt.py'),
                    '--adb', args.adb, '--out', str(capture)], check=True)
    record = json.loads((capture / 'capture.json').read_text())
    sys.path.insert(0, str(args.official_dual_sys.resolve()))
    import gpt
    layout = load('sony_layout', DEVICE / 'ci/dual_sys/sony_layout.py')
    before_a = (capture / 'gpt-primary-region.bin').read_bytes()
    before_b = (capture / 'gpt-backup-region.bin').read_bytes()
    after_a, after_b, plan = layout.plan(before_a, before_b, record['sector_bytes'],
                                        record['disk_bytes'] // record['sector_bytes'], 64 << 30, gpt)
    helper = args.refresh_helper.read_bytes()
    if helper[:6] != b'\x7fELF\x02\x01' or int.from_bytes(helper[18:20], 'little') != 183:
        raise ValueError('Need compiled AArch64 refresh helper')
    bundle = args.out / 'bundle'
    bundle.mkdir()
    protected = read('sha256sum /dev/block/sda52 /dev/block/sda97')
    if len(protected.splitlines()) != 2:
        raise ValueError('Protected partition hashing failed')
    kernel = read('uname -r').decode().strip()
    boot = read('cat /proc/sys/kernel/random/boot_id').decode().strip()
    files = {'gpt-primary.before': before_a, 'gpt-backup.before': before_b,
             'gpt-primary.after': after_a, 'gpt-backup.after': after_b,
             'sony-discard-apply.sh': (DEVICE / 'ci/dual_sys/sony-discard-apply.sh').read_bytes().replace(b'\r\n', b'\n'),
             'sony-refresh': helper, 'PROTECTED': protected,
             'zero-marker.bin': bytes(1 << 20), 'root-manifest.bin': manifest,
             'plan.env': f'KERNEL={shlex.quote(kernel)}\nBOOT_ID={shlex.quote(boot)}\n'.encode()}
    for name, data in files.items():
        (bundle / name).write_bytes(data)
    (bundle / 'SHA256SUMS').write_bytes(''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                                              for name, data in files.items()).encode())
    remote = '/tmp/sony-dual-' + boot[:8] + '-' + plan['unixnu']['guid'][:8]
    plan.update(serial=SERIAL, recovery_boot_id=boot, kernel=kernel, remote_bundle=remote,
                created_utc=datetime.now(timezone.utc).isoformat(), data_mode='discard, Android init/vold reformat',
                metadata_mutation=False, ios27_install_plan='ios27-install-plan.json',
                deployable=True, device_write_interface=True, execute_requested=args.execute,
                before_sha256={'primary': hashlib.sha256(before_a).hexdigest(), 'backup': hashlib.sha256(before_b).hexdigest()},
                after_sha256={'primary': hashlib.sha256(after_a).hexdigest(), 'backup': hashlib.sha256(after_b).hexdigest()})
    (args.out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    subprocess.run([*adb, 'push', str(bundle), remote], check=True, timeout=120)
    read(f'chmod 700 {remote}/sony-refresh')
    command = f'sh {remote}/sony-discard-apply.sh'
    checked = read(command + ' check')
    (args.out / 'check.log').write_bytes(checked)
    if b'CHECK OK; no block-device writes' not in checked:
        raise ValueError('Missing successful check marker')
    if not args.execute:
        print('CHECK PASSED; no block-device writes; bundle ' + remote)
        return
    result = {'apply_invoked': True, 'automatic_retries': False}
    (args.out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
    try:
        for stage, suffix in [('apply', ' apply ' + shlex.quote(CONFIRM)), ('refresh', ' refresh')]:
            done = subprocess.run([*adb, 'shell', '-T', command + suffix], capture_output=True, timeout=180)
            (args.out / (stage + '.stdout')).write_bytes(done.stdout)
            (args.out / (stage + '.stderr')).write_bytes(done.stderr)
            done.check_returncode()
            expected_marker = b'GPT COMPLETE' if stage == 'apply' else b'Kernel partition96 resized; partition98 added.'
            if expected_marker not in done.stdout:
                raise ValueError('Missing successful stage marker: ' + stage)
            result[stage + '_completed'] = True
            (args.out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
        for side, text, expected in [('primary', 'dd if=/dev/block/sda bs=4096 count=6 status=none', after_a),
                                     ('backup', 'dd if=/dev/block/sda bs=4096 skip=62461947 count=5 status=none', after_b)]:
            raw = read(text, binary=True)
            (args.out / ('gpt-' + side + '.readback')).write_bytes(raw)
            if raw != expected:
                raise ValueError('Host readback mismatch: ' + side)
        raw = read('blockdev --getsize64 /dev/block/sda96; blockdev --getsize64 /dev/block/sda98; cat /sys/class/block/sda98/start')
        (args.out / 'kernel-views.txt').write_bytes(raw)
        if raw.split() != [b'162799460352', b'68719476736', b'365434880']:
            raise ValueError('Kernel views differ')
        if read(command + ' verify').splitlines()[-1].split()[-1:] != [b'OK']:
            raise ValueError('Final protected hash verification failed')
        result.update(gpt_host_readback_verified=True, kernel_views_verified=True,
                      android_encrypted_data_initialized=False, ios27_images_written=False)
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        for name, text in [('recovery-stage.txt', f'cat {remote}/stage'), ('recovery-dmesg.txt', 'dmesg')]:
            try:
                (args.out / name).write_bytes(read(text))
            except Exception as error:
                result[name + '_capture_error'] = repr(error)
        (args.out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
