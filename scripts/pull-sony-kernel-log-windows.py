#!/usr/bin/env python3
"""Pull the UniXNU diagnostic log window from the handset and decode it.

The kernel writes the log window with log=1: the last 32 MiB of the `unixnu`
partition, plus the 256 MiB export region below it. This reads them from the
recovery shell over ADB and decodes them with the reviewed reader.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adbroot as A

PARTITION = '/dev/block/sda98'
PARTITION_BYTES = 68719476736
BLOCK = 4096
LOG_BLOCKS = 8192            # NativeUfs kLogReserveBlocks
EXPORT_BLOCKS = 65536        # NativeUfs kExportBlocks
READER = Path('/mnt/e/UniXNU-sheng27-sony-20261113/sources/sheng/scripts/read-sheng-log.py')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--reader', type=Path, default=READER)
    p.add_argument('--export', action='store_true', help='Also pull the 256 MiB export region')
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    total_blocks = PARTITION_BYTES // BLOCK
    log_first = total_blocks - LOG_BLOCKS
    export_first = log_first - EXPORT_BLOCKS
    if export_first < 0:
        raise ValueError('partition too small for the log window')

    remote = '/tmp/unixnu-log'
    A.sh(f'mkdir -p {remote}')
    A.sh(f'dd if={PARTITION} of={remote}/log.bin bs={BLOCK} skip={log_first} count={LOG_BLOCKS} status=none')
    if args.export:
        A.sh(f'dd if={PARTITION} of={remote}/export.bin bs={BLOCK} skip={export_first} count={EXPORT_BLOCKS} status=none')
    pulled = subprocess.run([A.ADB, '-s', A.SERIAL, 'pull', f'{remote}/log.bin', str(args.out / 'log.bin')],
                            capture_output=True, timeout=1800)
    (args.out / 'pull.log').write_bytes(pulled.stdout + pulled.stderr)
    pulled.check_returncode()
    data = (args.out / 'log.bin').read_bytes()
    if len(data) != LOG_BLOCKS * BLOCK:
        raise ValueError(f'unexpected log window size: {len(data)}')
    (args.out / 'log-window.json').write_text(json.dumps(dict(
        partition=PARTITION, log_first_block=log_first, log_blocks=LOG_BLOCKS,
        export_first_block=export_first, export_blocks=EXPORT_BLOCKS,
        log_sha256=hashlib.sha256(data).hexdigest()), indent=2) + '\n')
    print('log window:', len(data), 'bytes, sha256', hashlib.sha256(data).hexdigest())

    decoded = subprocess.run(['python3', '-B', str(args.reader), '--decode', str(args.out / 'log.bin'),
                              '--out', str(args.out / 'decoded')], capture_output=True, timeout=900)
    (args.out / 'decode.log').write_bytes(decoded.stdout + decoded.stderr)
    print(decoded.stdout.decode(errors='replace'))
    if decoded.returncode:
        print(decoded.stderr.decode(errors='replace'))
        raise SystemExit('reader failed; see decode.log')
    for name in ('header.txt', 'msgbuf.txt', 'latest.txt', 'slots.txt'):
        path = args.out / 'decoded' / name
        if path.exists():
            print(f'--- {name} ---')
            print(path.read_text(errors='replace')[:8000])


if __name__ == '__main__':
    main()
