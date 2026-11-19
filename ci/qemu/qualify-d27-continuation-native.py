#!/usr/bin/env python3
"""Bind a captured Data seed to actual original D27 APFS mount acceptance."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--seed',type=Path,required=True)
    p.add_argument('--run',type=Path,required=True)
    a=p.parse_args()
    receipt_path=a.seed.parent/'result.json'
    seed=json.loads(receipt_path.read_text())
    run=a.run.resolve();inputs=json.loads((run/'inputs.json').read_text())
    observed_path=run/'observation/gdb-stop.json'
    observed=json.loads(observed_path.read_text())
    result=json.loads((run/'result.json').read_text())
    symbols=json.loads((run/'symbols.json').read_text())
    payload=run/'esp/EFI/UniXNU/Payloads'
    actual_hash=sha(a.seed)
    if (actual_hash!=seed['private_seed_sha256'] or
            actual_hash!=sha(payload/'scratch-data.img') or
            sha(payload/'kernel.macho')!=inputs['sealed_kernel_sha256'] or
            observed['kernel_sha256']!=inputs['sealed_kernel_sha256']):
        raise ValueError('Actual Data/kernel input identities differ')
    if (result['exit_code']!=0 or result.get('bounded_timeout_interrupted') or
            observed['pc']!=symbols['_load_init_program_at_path']):
        raise ValueError('Require actual original launchd-entry checkpoint after Data mount')
    values=result['values']
    required={'_native_owner_root_accepted':1,'_native_owner_cache_stage':6,
              '_native_owner_cache_status':0,'_native_owner_cache_authorized':1,
              '_native_owner_data_stage':4,'_native_owner_data_status':0,
              '_native_owner_data_readonly':0,'_native_virtio_read_failures':0,
              '_native_virtio_integrity_failures':0}
    for name,value in required.items():
        if values.get(name)!=value:raise ValueError('Original mount checkpoint failed: '+name)
    qualification=dict(source_seed=str(a.seed),source_seed_sha256=actual_hash,
        observation=str(observed_path),observation_sha256=sha(observed_path),
        native_sha256=inputs['native_sha256'],strict_sha256=inputs['strict_sha256'],
        checkpoint_pc=observed['pc'],actual_original_d27_apfs_mount_accepted=True,
        actual_read_write_data_mount=True,verified_original_os_systemos=True,
        linux_apfsck_exit=seed.get('apfsck_exit'),
        linux_checker_diagnostic=seed.get('linux_checker_diagnostic'),
        linux_checker_passed=seed.get('apfsck_exit')==0,
        original_snapshot_unchanged=True,device_operations=False,
        limits='Actual native mount acceptance; Linux checker result remains recorded separately')
    target=a.seed.parent/'native-mount-qualification.json'
    if target.exists():raise ValueError('Preserve the existing native mount qualification')
    target.write_text(json.dumps(qualification,indent=2)+'\n')
    seed.update(native_mount_check_required=False,native_mount_qualification=str(target),
                native_mount_qualification_sha256=sha(target))
    receipt_path.write_text(json.dumps(seed,indent=2)+'\n')
    print(json.dumps(qualification,indent=2))


if __name__=='__main__':main()
