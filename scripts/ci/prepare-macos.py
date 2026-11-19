#!/usr/bin/env python3
"""Stage pinned source-only overlays before the official macOS kernel build."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tomllib

DEVICE=Path(__file__).resolve().parents[2]
PRELINK_BASELINE='9b950f2e104da77f494e8f2735c6f044f0e4db4d'
ARCH_ANCHOR='../../../../../patches/xnu-12377/native-pac-keys.patch'


def digest(data):
    return hashlib.sha256(data.replace(b'\r\n',b'\n')).hexdigest()


def reference_pin(text):
    """Return the UniXNU/UniXNU ref the vendored Sheng workflow checks out."""
    lines=text.splitlines()
    for index,line in enumerate(lines):
        if line.strip()=='repository: UniXNU/UniXNU':
            for follow in lines[index+1:index+6]:
                if follow.strip().startswith('ref:'):
                    return follow.split('ref:',1)[1].split('#',1)[0].strip()
    raise RuntimeError('Vendored Sheng workflow does not pin UniXNU/UniXNU')


def stage_profile(device, mainline):
    board=tomllib.loads((device/'board.toml').read_text())
    name=board['board']['os_profile']
    if Path(name).name!=name:raise RuntimeError('Invalid OS profile name')
    source=device/'profiles'/name
    target=mainline/'profiles/os'/name
    if not (source/'profile.toml').is_file():raise RuntimeError('Device OS profile is absent')
    if target.exists():raise RuntimeError('Refuse to replace an OS profile in pinned mainline')
    shutil.copytree(source,target)
    return {str(p.relative_to(target)):digest(p.read_bytes()) for p in target.rglob('*') if p.is_file()}


def insert_arch_patch(mainline, name, data):
    """Insert the device patch after the audited arm64e anchor or fail with the series."""
    arch=mainline/'profiles/arch/arm64e/patches/xnu'
    target=arch/name
    if target.exists():raise RuntimeError('Pinned mainline unexpectedly contains this local patch')
    series=arch/'series'
    lines=series.read_text().splitlines()
    if lines.count(ARCH_ANCHOR)!=1:
        raise RuntimeError('Architecture patch order differs from the audited arm64e series: '
                           + repr(lines))
    target.write_bytes(data.replace(b'\r\n',b'\n'))
    lines.insert(lines.index(ARCH_ANCHOR)+1,name)
    series.write_text('\n'.join(lines)+'\n')
    return arch


def apply_mainline_patch(mainline, data):
    data=data.replace(b'\r\n',b'\n')
    for flags in (['--check'],[]):
        try:
            subprocess.run(['git','-C',str(mainline),'apply',*flags,'-'],
                           input=data,capture_output=True,check=True)
        except subprocess.CalledProcessError as error:
            raise RuntimeError('Mainline source patch failed: '+error.stderr.decode(errors='replace')) from error


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mainline',required=True,type=Path)
    parser.add_argument('--component',required=True,type=Path)
    parser.add_argument('--vendor',required=True,type=Path,
                        help='Vendored copy of the current UniXNU-sheng workflow')
    parser.add_argument('--expected-unixnu-revision',required=True,
                        help='UniXNU ref the workflow checks out')
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    mainline=args.mainline.resolve(strict=True)
    expected=args.expected_unixnu_revision.strip()
    vendor_text=args.vendor.read_text(encoding='utf-8')
    if reference_pin(vendor_text)!=expected:
        raise RuntimeError('Vendored Sheng workflow pins another UniXNU revision: '+reference_pin(vendor_text))
    manifest=json.loads((DEVICE/'ci/source-overlays.json').read_text())
    if manifest['prelink_revision']!=PRELINK_BASELINE:
        raise RuntimeError('XnuPrelink baseline moved from the audited '+PRELINK_BASELINE)
    device=tomllib.loads((DEVICE/'board.toml').read_text())
    reference_command='build-fileset-release-reference.py --tree . --lto'
    if device['kernel']['archives'][-1]!=reference_command:
        raise RuntimeError('RELEASE-LTO comparison must follow its dependencies')
    revision=subprocess.check_output(['git','-C',str(mainline),'rev-parse','HEAD'],text=True).strip()
    if revision!=expected:raise RuntimeError(f'Mainline revision {revision} differs from the workflow pin {expected}')
    profile_files=stage_profile(DEVICE,mainline)
    if args.component.exists():raise RuntimeError('Refuse to replace a component checkout')
    subprocess.run(['git','clone','--filter=blob:none','--no-checkout',
                    'https://github.com/UniXNU/XnuPrelink.git',str(args.component)],check=True)
    subprocess.run(['git','-C',str(args.component),'checkout','--detach',manifest['prelink_revision']],check=True)
    component=args.component.resolve(strict=True)
    verified={}
    for entry in manifest['component_files']:
        relative=Path(entry['path'])
        if relative.is_absolute() or '..' in relative.parts:raise RuntimeError('Invalid overlay path')
        source=DEVICE/'ci/XnuPrelink'/relative
        data=source.read_bytes()
        if digest(data)!=entry['sha256_lf']:raise RuntimeError('Source overlay digest changed: '+str(relative))
        target=component/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data.replace(b'\r\n',b'\n'))
        verified[relative.as_posix()]=digest(target.read_bytes())
    patch=manifest['arch_patch']
    data=(DEVICE/'ci'/patch['path']).read_bytes()
    if digest(data)!=patch['sha256_lf']:raise RuntimeError('Architecture patch changed')
    insert_arch_patch(mainline,'native-metaclass-vptr-poison.patch',data)
    architecture_patch_digest=digest(data)
    mainline_patches={}
    for patch in manifest.get('mainline_patches',[]):
        relative=Path(patch['path'])
        if relative.is_absolute() or '..' in relative.parts:raise RuntimeError('Invalid mainline patch path')
        data=(DEVICE/'ci'/relative).read_bytes()
        if digest(data)!=patch['sha256_lf']:raise RuntimeError('Mainline patch changed: '+str(relative))
        apply_mainline_patch(mainline,data)
        mainline_patches[relative.as_posix()]=digest(data)
    report={'unixnu_revision':revision,
            'unixnu_revision_source':'vendored Sheng main workflow',
            'PRELINK_BASELINE':manifest['prelink_revision'],
            'device_os_profile_files':profile_files,
            'device_revision':subprocess.check_output(['git','-C',str(DEVICE),'rev-parse','HEAD'],text=True).strip(),
             'component_sources':verified,'architecture_patch_sha256':architecture_patch_digest,
             'architecture_patch_anchor':ARCH_ANCHOR,
             'mainline_patches':mainline_patches,
            'reference_build':'build-fileset-release-reference.py --tree . --lto',
            'runtime_configuration':'DEVELOPMENT / non-LTO / chained input for fileset prelink',
            'allow_missing':False,'proprietary_inputs_published':False}
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print('Pinned source overlays and patch order verified')


if __name__=='__main__':main()
