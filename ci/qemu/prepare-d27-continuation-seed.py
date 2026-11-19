#!/usr/bin/env python3
"""Verify an actual stopped-guest Data snapshot for a later QEMU continuation."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot',type=Path,required=True)
    p.add_argument('--receipt',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--native-mount-check',action='store_true',help='Stage a private copy for an original D27 APFS checkpoint when the Linux checker rejects it')
    a=p.parse_args()
    if shutil.disk_usage('/mnt/g').free<8*1024**3:raise ValueError('G reserve below8GiB')
    received=json.loads(a.receipt.read_text())
    if 'data_snapshot' in received:received=received['data_snapshot']
    elif 'pm_workloop' in received:received=received['pm_workloop']['data_snapshot']
    if not received.get('read_only') or not received.get('guest_stopped'):
        raise ValueError('Require an actual stopped guest capture')
    if received.get('current_loader_input_compatible') is False:
        raise ValueError('Complete raw snapshot is retained; it exceeds the current packed loader input and needs a separate Data backend')
    if sha(a.snapshot)!=received['packed_sha256']:raise ValueError('Captured seed hash differs')
    sys.path.insert(0,str(BASE/'sources/UniXNU/drivers/DarwinBoot/Test'))
    import packed_ramdisk
    metadata,header=packed_ramdisk.inspect(a.snapshot)
    if metadata['sha256']!=received['raw_sha256'] or header[32:36]!=b'NXSB':
        raise ValueError('Complete captured Data reconstruction differs')
    a.out.mkdir(parents=True,exist_ok=False)
    raw=a.out/'Data.raw'
    logical,extents=packed_ramdisk.regions(a.snapshot.read_bytes())
    with raw.open('xb') as f:
        f.truncate(logical)
        for at,data in extents:f.seek(at);f.write(data)
    tools=json.loads(Path('/root/unixnu-build/venus-apfs-tools/inputs.json').read_text())
    with (a.out/'apfsck.log').open('x') as log:
        done=subprocess.run([tools['apfsck'],str(raw)],stdout=log,stderr=subprocess.STDOUT,timeout=180)
    # Preserve any dirty snapshot and checker report. A rejected filesystem is
    # not silently installed as the next seed or treated as an empty disk.
    if done.returncode and not a.native_mount_check:raise ValueError('Captured APFS needs recovery; preserve this snapshot and apfsck.log')
    target=a.out/'scratch-data.img'
    shutil.copyfile(a.snapshot,target)
    original=Path('/mnt/host-e/UniXNU-Port-artifacts/qemu-validation-20261117-002/esp/EFI/UniXNU/Payloads/scratch-data.img')
    expected='23cd7aa2db7b26eae5d30b956d840f475c45017893077005a8b8ce87e44b584d'
    if sha(original)!=expected:raise ValueError('Original retained seed changed')
    record=dict(private_seed_sha256=sha(target),source_snapshot=str(a.snapshot),
                source_snapshot_receipt=str(a.receipt),source_snapshot_sha256=received['packed_sha256'],
                raw_sha256=received['raw_sha256'],logical_bytes=logical,apfsck_exit=done.returncode,
                actual_prior_guest_data=True,original_seed_sha256=expected,original_seed_unchanged=True,
                same_data_volume_identity=True,new_blank_seed_created=False,device_operations=False,
                native_mount_check_required=done.returncode!=0,
                linux_checker_diagnostic=(a.out/'apfsck.log').read_text().strip())
    (a.out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2),flush=True)


if __name__=='__main__':main()
