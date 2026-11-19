#!/usr/bin/env python3
"""Stream the two original D27 readonly images into the reviewed unixnu slice.

Never writes Android userdata, boot, metadata, rddata or an entire UFS disk.
Commit the official root manifest only after both full readback hashes match.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

DEVICE = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', required=True)
    p.add_argument('--layout', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--execute', action='store_true')
    p.add_argument('--resume-incomplete', type=Path,
                   help='Explicit inspected recovery of an incomplete image install, never a GPT retry')
    args = p.parse_args()
    if not args.execute:
        p.error('Use --execute only for the already authorized installation')
    state = json.loads((args.layout / 'execution.json').read_text())
    if not all(state.get(k) is True for k in ('gpt_host_readback_verified', 'kernel_views_verified')):
        raise ValueError('Need a successfully applied and refreshed layout')
    layout = json.loads((args.layout / 'plan.json').read_text())
    installed = json.loads((args.layout / 'ios27-install-plan.json').read_text())
    spec = importlib.util.spec_from_file_location('sony_install', DEVICE / 'ci/dual_sys/sony_install.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest, expected = module.manifest()
    for window, source in zip(expected['windows'], installed['windows'], strict=True):
        if any(window[k] != source[k] for k in window):
            raise ValueError('Installation plan differs from reviewed fixed windows')
        image = Path(source['host_image'])
        with image.open('rb') as stream:
            if image.stat().st_size != window['bytes'] or hashlib.file_digest(stream, 'sha256').hexdigest() != window['sha256']:
                raise ValueError('Source image changed: ' + window['name'])
        window['host_image'] = str(image)
    args.out.mkdir(exist_ok=False, parents=True)
    adb = [args.adb, '-s', 'PDX_DEVICE_SERIAL']
    remote = layout['remote_bundle']
    if not remote.startswith('/tmp/sony-dual-') or any(c not in '/-abcdefghijklmnopqrstuvwxyz0123456789' for c in remote):
        raise ValueError('Unexpected remote path')
    guard = f'''set -eu
set -o pipefail
sh {remote}/sony-discard-apply.sh verify >/dev/null
[ "$(blockdev --getsize64 /dev/block/sda96)" = 162799460352 ]
[ "$(blockdev --getsize64 /dev/block/sda98)" = 68719476736 ]
[ "$(cat /sys/class/block/sda98/start)" = 365434880 ]
[ "$(cat /sys/class/block/sda98/size)" = 134217728 ]
for part in sda96 sda98 sda52; do
    [ -z "$(find /sys/class/block/$part/holders -mindepth 1 -maxdepth 1)" ]
    dev=$(cat /sys/class/block/$part/dev)
    for info in /proc/[0-9]*/mountinfo; do
        [ -r "$info" ] || continue
        while read -r mount_id parent mounted root point rest; do
            [ "$mounted" != "$dev" ]
            case "$point" in /data|/metadata) exit 1 ;; esac
        done < "$info"
    done
done
'''

    def read(command, timeout=120, binary=False):
        mode = ['exec-out'] if binary else ['shell', '-T']
        done = subprocess.run([*adb, *mode, command], capture_output=True, timeout=timeout)
        if done.returncode:
            raise RuntimeError(f'Remote exit{done.returncode}: ' + done.stderr.decode(errors='replace'))
        return done.stdout if binary else done.stdout.replace(b'\r\n', b'\n')

    if args.resume_incomplete:
        previous = json.loads((args.resume_incomplete / 'execution.json').read_text())
        if 'error' not in previous or previous.get('readonly_system_images_installed'):
            raise ValueError('Resume only an inspected incomplete installation')
        read(guard + 'test -d /tmp/sony-ios27-install.lock\n')
        if read(guard + 'dd if=/dev/block/sda98 bs=4096 count=1 status=none\n', binary=True) != bytes(4096):
            raise ValueError('Resume requires an uncommitted all-zero root manifest')
    else:
        read(guard + 'mkdir /tmp/sony-ios27-install.lock\n')
    result = dict(started_utc=datetime.now(timezone.utc).isoformat(), partition='/dev/block/sda98',
                  partition_label='unixnu', windows=[], automatic_retries=False,
                  boot_partitions_written=False, android_userdata_written=False,
                  persistent_data_initialized=False, persistent_logs_enabled=False,
                  boot_entry_enabled=False, springboard_verified=False)
    if args.resume_incomplete:
        result['explicit_inspected_resume_of'] = str(args.resume_incomplete.resolve())
        result['transport_replacement'] = 'ADB sync push to RAM; per-chunk upload hash and bounded checked dd with per-chunk readback'
    (args.out / 'install-plan.json').write_text(json.dumps(expected, indent=2) + '\n')

    def record():
        (args.out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')

    def marker(text):
        read("printf '%s\\n' " + shlex.quote(text) + f' > {remote}/install-stage')

    def hash_window(offset, size):
        command = guard + f'dd if=/dev/block/sda98 bs=1048576 skip={offset} count={size} iflag=skip_bytes,count_bytes status=none | sha256sum\n'
        value = read(command, timeout=1800).decode().split()
        if len(value) != 2 or len(value[0]) != 64:
            raise ValueError('Malformed readback hash')
        return value[0]

    try:
        marker('Invalidating unixnu manifest before payload writes')
        # Both the old on-disk manifest and unused prefix padding are invalid until commit.
        read(guard + f'dd if={remote}/zero-marker.bin of=/dev/block/sda98 bs=4096 count=256 conv=notrunc,fsync\n')
        # Stage only512MiB in recovery RAM. Windows ADB's shell/exec streaming
        # paths have different byte/completion semantics; sync push avoids both.
        temp_root = Path.home() / 'AppData/Local/Temp/opencode'
        if not temp_root.is_dir():
            raise ValueError('Approved Windows staging directory unavailable')
        chunk_file = None
        remote_chunk = f'{remote}/ios27-upload.chunk'
        for window in expected['windows']:
            name, size, offset = window['name'], window['bytes'], window['offset']
            marker('Writing readonly D27 ' + name)
            print(f'Writing {name}: {size} bytes at unixnu+{offset}', flush=True)
            chunks = []
            with Path(window['host_image']).open('rb') as stream:
                position = 0
                while position < size:
                    length = min(512 << 20, size - position)
                    digest = hashlib.sha256()
                    with tempfile.NamedTemporaryFile(prefix='sony-ios27-', suffix='.chunk',
                                                     dir=temp_root, delete=False) as temp:
                        chunk_file = Path(temp.name)
                        remaining = length
                        while remaining:
                            block = stream.read(min(1 << 20, remaining))
                            if not block:
                                raise ValueError('Unexpected source EOF')
                            temp.write(block)
                            digest.update(block)
                            remaining -= len(block)
                    expected_hash = digest.hexdigest()
                    pushed = subprocess.run([*adb, 'push', str(chunk_file), remote_chunk],
                                            capture_output=True, timeout=180)
                    (args.out / f'{name}.chunk-{position}.push.log').write_bytes(pushed.stdout+pushed.stderr)
                    pushed.check_returncode()
                    upload = read(f'stat -c %s {remote_chunk}; sha256sum {remote_chunk}').decode().split()
                    if len(upload) != 3 or upload[0] != str(length) or upload[1] != expected_hash:
                        raise ValueError('RAM upload differs')
                    absolute = offset + position
                    if absolute % 4096 or length % 4096 or absolute + length > expected['partition_bytes']:
                        raise ValueError('Unaligned or out-of-partition chunk')
                    read(guard + f'dd if={remote_chunk} of=/dev/block/sda98 bs=4096 seek={absolute // 4096} count={length // 4096} conv=notrunc,fsync status=none\n', timeout=180)
                    actual = hash_window(absolute, length)
                    if actual != expected_hash:
                        raise ValueError(f'{name} chunk at {position} readback differs')
                    chunks.append(dict(offset=position, bytes=length, sha256=actual,
                                       ram_upload_verified=True, device_readback_verified=True))
                    (args.out / (name + '.chunks.json')).write_text(json.dumps(chunks, indent=2) + '\n')
                    chunk_file.unlink()
                    chunk_file = None
                    position += length
                    print(f'{name}: {position}/{size} bytes chunk readback PASS', flush=True)
            read(f'rm {remote_chunk}')
            marker('Full readback SHA256 for D27 ' + name)
            actual = hash_window(offset, size)
            if actual != window['sha256']:
                raise ValueError(name + ' readback SHA256 mismatch: ' + actual)
            result['windows'].append(dict(name=name, offset=offset, bytes=size, sha256=actual,
                                          full_device_readback_verified=True, verified_chunks=len(chunks)))
            record()
            print(name + ' full readback SHA256 PASS: ' + actual, flush=True)
        marker('Committing SHNGROOT manifest after both full readbacks')
        read(guard + f'dd if={remote}/root-manifest.bin of=/dev/block/sda98 bs=4096 count=1 conv=notrunc,fsync\nsync\n')
        actual = read(guard + 'dd if=/dev/block/sda98 bs=4096 count=1 status=none\n', binary=True)
        (args.out / 'root-manifest.readback.bin').write_bytes(actual)
        if actual != manifest:
            raise ValueError('Manifest readback differs')
        read(guard + f'''if [ -e /dev/block/by-name/unixnu ]; then
    [ "$(readlink -f /dev/block/by-name/unixnu)" = /dev/block/sda98 ]
else
    ln -s /dev/block/sda98 /dev/block/by-name/unixnu
fi
''')
        result.update(readonly_system_images_installed=True, root_manifest_readback_verified=True,
                      completed_utc=datetime.now(timezone.utc).isoformat(),
                      protected_partitions_unchanged=True, gpt_still_matches_applied_plan=True,
                      android_encrypted_data_initialization_pending=True,
                      post_reboot_partition_verification_pending=True)
        marker('OS/SystemOS/manifest readback PASS; no iOS boot readiness claimed')
        print(json.dumps(result, indent=2), flush=True)
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        record()
        try:
            (args.out / 'recovery-stage.txt').write_bytes(read(f'cat {remote}/install-stage'))
        except Exception:
            pass


if __name__ == '__main__':
    main()
