#!/usr/bin/env python3
"""Strict iPhone14 fileset prelink of a named native build; preserve all failed artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

DEVICE=Path(__file__).resolve().parents[1]
PROJECT=DEVICE.parents[1]


def digest(path):
    with path.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()


def checked_copy(source, target):
    """Copy bytes, not an NTFS symlink, and verify the completed transfer."""
    shutil.copyfile(source, target)
    if digest(source)!=digest(target):raise RuntimeError(f'Copy changed bytes: {source}')


def work_filesystem(root):
    filesystem=subprocess.check_output(['findmnt','-T',str(root),'-n','-o','FSTYPE'],text=True).strip()
    if filesystem!='ext4':raise RuntimeError(f'Prelink workspace must be ext4, not {filesystem}: {root}')
    return filesystem


def snapshot_tool(source, target):
    """Snapshot the exact analysis/emission sources without copying Git or caches."""
    target.mkdir()
    (target/'fixtures').mkdir()
    records={}
    for path in sorted([*source.glob('*.py'),*source.glob('fixtures/fileset-*-symbols.json')]):
        relative=path.relative_to(source)
        checked_copy(path,target/relative)
        records[relative.as_posix()]=digest(target/relative)
    return records


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt',required=True)
    parser.add_argument('--native',required=True,type=Path)
    parser.add_argument('--reference',required=True,type=Path)
    parser.add_argument('--work-root',type=Path,default=Path('/root/unixnu-build'),
                        help='Existing ext4 directory for inputs, tool snapshot and live output')
    parser.add_argument('--kernel-args',help='Exact planned boot arguments for the official source-provider POST seal')
    parser.add_argument('--allow-missing',action='store_true',
                        help='Documented experimental emission: unmatched calls reach unixnu_fileset_unmapped')
    args=parser.parse_args()
    if not args.attempt.isalnum():parser.error('Use a fresh alphanumeric attempt')
    profile=tomllib.loads((DEVICE/'profiles/ios-27.0.1-24A446-iphone14/profile.toml').read_text())
    original=DEVICE/'.cache/iphone14-ios27/ipsw/24A446/kernelcache.decompressed'
    if digest(original)!=profile['kernel']['prelink']['kernelcache_sha256']:
        raise RuntimeError('The iPhone14 original kernelcache changed')
    tool=PROJECT/'references/pdx234-XnuPrelink-20261108'
    revision=subprocess.check_output(['git','-C',str(tool),'rev-parse','HEAD'],text=True).strip()
    if revision!='9b950f2e104da77f494e8f2735c6f044f0e4db4d':raise RuntimeError('Reviewed prelink source changed')
    filesystem=work_filesystem(args.work_root)
    out=DEVICE/'out'/('iphone14-prelink-'+args.attempt)
    out.mkdir()
    work=args.work_root/('pdx234-iphone14-prelink-'+args.attempt)
    work.mkdir()
    staging=work/'inputs'
    staging.mkdir()
    sources={'native.macho':args.native,'reference.macho':args.reference,'original.macho':original}
    for name,source in sources.items():checked_copy(source,staging/name)
    source_hashes=snapshot_tool(tool,work/'tool')
    native_input_sha256=digest(args.native)
    board=tomllib.loads((DEVICE/'board.toml').read_text())
    boot_args=args.kernel_args if args.kernel_args is not None else ' '.join(board['payload']['kernel_args'])
    seal_record=None
    env=dict(os.environ,UNIXNU_XNU_ARCH=profile['os']['arch'],UNIXNU_IOS_VERSION=profile['os']['ios_version'])
    if b'_source_corecrypto14_bootstrap\0' in (staging/'native.macho').read_bytes():
        # static_if setup changes instructions before POST. Seal those final
        # native instructions before placement, then reseal after emission.
        sealer=PROJECT/'references/pdx234-mainline-20261108/scripts/seal-source-crypto-kernel.py'
        seal_command=[sys.executable,'-B',str(sealer),str(staging/'native.macho'),'--kernel-args',boot_args]
        with (work/'native-seal.log').open('x') as log:
            seal=subprocess.run(seal_command,env=env,stdout=log,stderr=subprocess.STDOUT)
        checked_copy(work/'native-seal.log',out/'native-seal.log')
        if seal.returncode:raise RuntimeError('Official native POST seal failed; see '+str(work/'native-seal.log'))
        seal_record=json.loads((staging/'native.macho.crypto-hmac.json').read_text())
        seal_record['tool_sha256']=digest(sealer)
    command=[sys.executable,'-u','-B',str(work/'tool/emit_prelink.py'),'--kernel',str(staging/'native.macho'),
        '--prelinked',str(staging/'original.macho'),'--fileset-reference',str(staging/'reference.macho'),'--slide=0',
        '--output',str(work/'kernel.macho')]
    for root in profile['kernel']['prelink']['roots']:command.extend(['--root',root])
    early=profile['kernel']['prelink'].get('early_security_init')
    if early:
        # Documented prelockdown policy initializer from the selected original component.
        command.extend(['--early-security-init',early])
    if args.allow_missing:command.append('--allow-missing')
    inputs={'command':command,'native_sha256':digest(staging/'native.macho'),'reference_sha256':digest(args.reference),
        'source_native_sha256':native_input_sha256,'native_post_seal':seal_record,'kernel_args':boot_args,
        'original_sha256':digest(original),'prelink_revision':revision,'allow_missing':args.allow_missing,
        'experimental_image':args.allow_missing,
        'prelink_layout_sha256':digest(tool/'fileset_layout.py'),
        'prelink_source_sha256':source_hashes,
        'work_dir':str(work),'work_filesystem':filesystem,
        'source_inputs':{name:str(source.resolve()) for name,source in sources.items()},
        'device_operations':False,'springboard_verified':False}
    (work/'inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    checked_copy(work/'inputs.json',out/'inputs.json')
    print('Strict prelink ext4 log: '+str(work/'prelink.log'),flush=True)
    with (work/'prelink.log').open('x') as log:
        result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
    if result.returncode==0 and seal_record is not None:
        final_command=[sys.executable,'-B',str(sealer),str(work/'kernel.macho'),'--kernel-args',boot_args]
        with (work/'final-seal.log').open('x') as log:
            result=subprocess.run(final_command,env=env,stdout=log,stderr=subprocess.STDOUT)
        if result.returncode:raise RuntimeError('Official final POST seal failed; ext4 candidate is not qualified')
        inputs['final_post_seal']=json.loads((work/'kernel.macho.crypto-hmac.json').read_text())
    inputs['exit_code']=result.returncode
    inputs['candidate_exists']=(work/'kernel.macho').is_file()
    (work/'execution.json').write_text(json.dumps(inputs,indent=2)+'\n')
    for path in sorted(work.iterdir()):
        if path.is_file() and path.name!='inputs.json':checked_copy(path,out/path.name)
    print('\n'.join((work/'prelink.log').read_text(errors='replace').splitlines()[-35:]))
    raise SystemExit(result.returncode)


if __name__=='__main__':main()
