#!/usr/bin/env python3
"""Install the D27 root policy-table objects and the version-2 SHNGROOT manifest.

Scope: the `unixnu` partition (/dev/block/sda98) only. The two readonly D27
system windows are never written; they are only hashed. The manifest block is
committed last, exactly like the reviewed v1 installation.

Never touches Android userdata, boot, metadata, rddata, the GPT or a whole UFS disk.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adbroot as A

DEVICE = Path(__file__).resolve().parents[1]

PARTITION = '/dev/block/sda98'
PARTITION_BYTES = 68719476736
PARTITION_START_512 = 365434880
PARTITION_SIZE_512 = 134217728

WINDOWS = [
    dict(name='OS', offset=1048576, bytes=9537847296,
         sha256='5371e392912dbc5f6f9677d4987c726e15fd7afc519b3644d8d6694777182ad5'),
    dict(name='SystemOS', offset=9538895872, bytes=6012534784,
         sha256='34b6010eb6329ca1c942c374df1b157c40cfc36b1120b0c2ec811ea69ed3b686'),
]
OBJECTS = [
    dict(name='OS.vroot', offset=15551430656, bytes=74514432,
         sha256='27d67b28d701edd759d9aaa2e27b62ee3a96933323f7854fae72fcc7d889b3c4'),
    dict(name='SystemOS.vroot', offset=15626928128, bytes=46972928,
         sha256='620855ef70f4865f4fbbea3de1306c72e8f4ac4382c6123f2c302e32355fd3aa'),
]
V1_MANIFEST_SHA256 = '6f09dc9979ead7cd22318085ec374dd7fad439e5c3713620def6d93ecac73a05'
REMOTE = '/tmp/sheng27-root-objects'


def guard():
    checks = {
        'identity': "getprop ro.product.device | grep -qx pdx234",
        'root': 'test "$(id -u)" = 0',
        'partition_alias': f'test "$(readlink -f /dev/block/by-name/unixnu)" = {PARTITION}',
        'partition_bytes': f'test "$(blockdev --getsize64 {PARTITION})" = {PARTITION_BYTES}',
        'partition_start': f'test "$(cat /sys/class/block/sda98/start)" = {PARTITION_START_512}',
        'partition_sectors': f'test "$(cat /sys/class/block/sda98/size)" = {PARTITION_SIZE_512}',
        'no_holders': 'test -z "$(find /sys/class/block/sda98/holders -mindepth 1 -maxdepth 1)"',
        'not_mounted': '! grep -q " sda98 " /proc/mounts',
        'userdata_intact': 'test "$(blockdev --getsize64 /dev/block/sda96)" = 162799460352',
        'lock_free': f'test ! -e {REMOTE}.lock',
    }
    for name, command in checks.items():
        A.sh(command)
    return checks


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--objects', required=True, type=Path,
                   help='Directory holding OS.vroot, SystemOS.vroot and root-manifest-v2.bin')
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--execute', action='store_true')
    args = p.parse_args()
    if not args.execute:
        p.error('Use --execute only for the already authorized installation')

    manifest_path = args.objects / 'root-manifest-v2.bin'
    sources = {name: args.objects / name for name in ('OS.vroot', 'SystemOS.vroot')}
    for path in [manifest_path, *sources.values()]:
        if not path.is_file():
            raise ValueError('missing input: ' + str(path))

    result = dict(started_utc=datetime.now(timezone.utc).isoformat(), partition=PARTITION,
                  partition_label='unixnu', device_writes=True, boot_partitions_written=False,
                  android_userdata_written=False, gpt_written=False, formatting=False,
                  objects=[], windows=[], manifest=None, springboard_verified=False)
    args.out.mkdir(parents=True, exist_ok=True)

    def record():
        (args.out / 'execution.json').write_text(json.dumps(result, indent=2) + '\n')

    def stage(text):
        A.text(f"mkdir -p {REMOTE}; printf '%s\\n' '{text}' > {REMOTE}/stage")

    try:
        checks = guard()
        result['guard'] = checks
        A.sh(f'mkdir {REMOTE}.lock')
        A.sh(f'mkdir -p {REMOTE}')

        # Baseline: the committed v1 manifest and the two readonly window edges.
        baseline = A.binary(f'dd if={PARTITION} bs=4096 count=1 status=none', 4096)
        baseline_sha = hashlib.sha256(baseline).hexdigest()
        if baseline_sha != V1_MANIFEST_SHA256:
            raise ValueError('unexpected manifest on the device: ' + baseline_sha)
        result['baseline_manifest_sha256'] = baseline_sha
        result['baseline_manifest_version'] = int.from_bytes(baseline[8:12], 'little')
        edges = {}
        for window in WINDOWS:
            head = A.binary(f'dd if={PARTITION} bs=4096 skip={window["offset"] // 4096} count=1 status=none', 4096)
            tail_lba = (window['offset'] + window['bytes']) // 4096 - 1
            tail = A.binary(f'dd if={PARTITION} bs=4096 skip={tail_lba} count=1 status=none', 4096)
            edges[window['name']] = dict(
                head_sha256=hashlib.sha256(head).hexdigest(),
                tail_sha256=hashlib.sha256(tail).hexdigest())
        result['baseline_window_edges'] = edges

        for obj in OBJECTS:
            source = sources[obj['name']]
            actual = A.sha256_file(source)
            if actual != obj['sha256'] or source.stat().st_size != obj['bytes']:
                raise ValueError('host object differs: ' + obj['name'])
            remote = f'{REMOTE}/{obj["name"]}'
            stage('Uploading ' + obj['name'])
            A.push(str(source), remote, timeout=1800)
            upload = A.text(f'stat -c %s {remote}; sha256sum {remote}').split()
            if len(upload) != 3 or upload[0] != str(obj['bytes']) or upload[1] != obj['sha256']:
                raise ValueError('RAM upload differs: ' + obj['name'])
            if obj['offset'] % 4096 or obj['bytes'] % 4096:
                raise ValueError('unaligned object')
            if obj['offset'] + obj['bytes'] > PARTITION_BYTES:
                raise ValueError('object outside the partition')
            seek = obj['offset'] // 4096
            count = obj['bytes'] // 4096
            stage('Writing ' + obj['name'])
            A.sh(f'dd if={remote} of={PARTITION} bs=4096 seek={seek} count={count} '
                 f'conv=notrunc,fsync status=none', timeout=1800)
            actual = A.range_sha256(obj['offset'], obj['bytes'])
            if actual != obj['sha256']:
                raise ValueError(obj['name'] + ' readback differs: ' + actual)
            result['objects'].append(dict(name=obj['name'], offset=obj['offset'], bytes=obj['bytes'],
                                          sha256=actual, ram_upload_verified=True,
                                          device_readback_verified=True))
            record()
            print(f'{obj["name"]}: device readback PASS {actual}', flush=True)
            A.sh(f'rm -f {remote}')

        # The readonly windows must still be byte-identical before the manifest is committed.
        stage('Verifying the readonly D27 windows')
        for window in WINDOWS:
            actual = A.range_sha256(window['offset'], window['bytes'])
            if actual != window['sha256']:
                raise ValueError(window['name'] + ' readback SHA256 mismatch: ' + actual)
            result['windows'].append(dict(name=window['name'], offset=window['offset'],
                                          bytes=window['bytes'], sha256=actual,
                                          full_device_readback_verified=True, readonly=True))
            record()
            print(f'{window["name"]}: full readback SHA256 PASS {actual}', flush=True)

        stage('Committing the version-2 SHNGROOT manifest')
        manifest_sha = A.sha256_file(manifest_path)
        A.push(str(manifest_path), f'{REMOTE}/root-manifest-v2.bin', timeout=300)
        A.sh(f'dd if={REMOTE}/root-manifest-v2.bin of={PARTITION} bs=4096 count=1 '
             f'conv=notrunc,fsync status=none\nsync', timeout=300)
        committed = A.binary(f'dd if={PARTITION} bs=4096 count=1 status=none', 4096)
        if committed != manifest_path.read_bytes():
            raise ValueError('manifest readback differs')
        result['manifest'] = dict(path=str(manifest_path), sha256=manifest_sha,
                                  bytes=manifest_path.stat().st_size,
                                  version=int.from_bytes(committed[8:12], 'little'),
                                  entries=int.from_bytes(committed[12:16], 'little'),
                                  image_bytes=int.from_bytes(committed[16:24], 'little'),
                                  readback_byte_identical=True)
        record()
        print('manifest readback PASS ' + manifest_sha, flush=True)

        # Final state: objects and manifest re-read after the commit.
        for obj in OBJECTS:
            actual = A.range_sha256(obj['offset'], obj['bytes'])
            if actual != obj['sha256']:
                raise ValueError(obj['name'] + ' final readback differs')
        final = A.binary(f'dd if={PARTITION} bs=4096 count=1 status=none', 4096)
        if hashlib.sha256(final).hexdigest() != manifest_sha:
            raise ValueError('final manifest readback differs')

        result.update(completed_utc=datetime.now(timezone.utc).isoformat(),
                      protected_partitions_unchanged=True, gpt_unchanged=True,
                      boot_entry_enabled=False, root_mount_verified=False,
                      springboard_verified=False,
                      note='The unixnu partition now carries the v2 manifest and the two D27 policy-table objects.')
        record()
        print(json.dumps(result, indent=2), flush=True)
    except BaseException as error:
        result['error'] = repr(error)
        record()
        raise


if __name__ == '__main__':
    main()
