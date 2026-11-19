#!/usr/bin/env python3
"""Apply target-qualified Setup and no-idle preferences to a private Data copy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

BASE=Path('/mnt/e/UniXNU-sheng27-sony-20261113')

def sha(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    for drive in ('e','f'):
        mount=Path('/mnt/host-'+drive);mount.mkdir(exist_ok=True)
        if not os.path.ismount(mount):subprocess.run(['mount','-t','drvfs',drive.upper()+':',str(mount),'-o','metadata'+(',ro' if drive=='e' else '')],check=True)
    a.out.mkdir(parents=True,exist_ok=False)
    original=Path('/mnt/host-e/UniXNU-Port-artifacts/qemu-validation-20261117-002/esp/EFI/UniXNU/Payloads/scratch-data.img')
    if sha(original)!='23cd7aa2db7b26eae5d30b956d840f475c45017893077005a8b8ce87e44b584d':raise ValueError('Original seed differs')
    sys.path.insert(0,str(BASE/'sources/UniXNU/drivers/DarwinBoot/Test'));import packed_ramdisk
    logical,extents=packed_ramdisk.regions(original.read_bytes())
    if logical>2*1024**3:raise ValueError('Volatile QEMU Data exceeds NativeRamBlock 2GiB limit')
    raw=a.out/'Data.raw'
    with raw.open('xb') as f:
        f.truncate(logical)
        for offset,data in extents:f.seek(offset);f.write(data)
    tools=Path('/root/unixnu-build/venus-apfs-tools');inputs=json.loads((tools/'inputs.json').read_text())
    initramfs=a.out/'initramfs'
    for name in ('bin','mods','dev','proc','sys','tmp','mnt/data','payload'):(initramfs/name).mkdir(parents=True,exist_ok=True)
    for name in ('bin/busybox','mods/00.ko','mods/01.ko'):shutil.copyfile(tools/'seed-attempt-1/initramfs'/name,initramfs/name)
    (initramfs/'bin/busybox').chmod(0o755)
    prefs={
        'com.apple.springboard':dict(BKNoWatchdogs=True,FBLaunchWatchdogExceptions={'com.apple.purplebuddy':100.0},MCForceShowCloudConfigurationUI=False,SBDisableAutoDim=True,SBDontDimOrLockOnAC=True,SBDisableIdleSleep=True),
        'com.apple.purplebuddy':dict(SetupDone=True,SetupFinishedAllSteps=True,SetupVersion=11,daemonizeNeedsToRun=False),
        'com.apple.purplebuddy.notbackedup':{k:False for k in ('ShouldRunDiagnosticsMiniBuddy','ShouldRunHSA2MiniBuddy','ShouldRunKeychainSyncMiniBuddy','ShouldRunMesaMiniBuddy','ShouldRunPaymentMiniBuddy','ShouldRunStandardMiniBuddy','SilentICDPUpgrade')},
        'com.apple.managedconfiguration.notbackedup':dict(LockdownActivationIndicatesCloudConfigurationAvailable=False),
        'com.apple.migration':dict(LastSystemVersion='24A446',DMUserDataDisposition=dict(SyntheticDidUpgrade=False,buildVersion='24A446')),
    }
    # First mount exports exact existing preferences as base64. Merge on the host
    # and mount a second time to install the merged values with real ownership.
    def linux_run(body,label):
        text='''#!/bin/busybox sh
/bin/busybox --install -s /bin
set -eu
trap 'echo D27_CURRENT_SEED_FAIL; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
insmod /mods/00.ko
insmod /mods/01.ko
mount -t apfs -o readwrite,cknodes /dev/vda /mnt/data
'''+body+'''
sync
umount /mnt/data
echo D27_CURRENT_SEED_PASS
trap - EXIT
poweroff -f
'''
        (initramfs/'init').write_text(text);(initramfs/'init').chmod(0o755)
        packed=a.out/(label+'.cpio')
        names=b'.\0'+b''.join(str(path.relative_to(initramfs)).encode()+b'\0' for path in sorted(initramfs.rglob('*')))
        with packed.open('wb') as f:subprocess.run(['cpio','--null','-o','--format=newc'],input=names,cwd=initramfs,stdout=f,stderr=subprocess.PIPE,check=True)
        command=['qemu-system-x86_64','-accel','tcg','-cpu','max','-m','1024','-smp','2','-kernel',inputs['kernel'],'-initrd',str(packed),'-append','console=ttyS0 quiet rdinit=/init panic=-1','-display','none','-monitor','none','-serial','stdio','-no-reboot','-nic','none','-drive',f'file={raw},format=raw,if=virtio']
        (a.out/(label+'-command.json')).write_text(json.dumps(command,indent=2)+'\n')
        with (a.out/(label+'.log')).open('x') as f:subprocess.run(command,stdout=f,stderr=subprocess.STDOUT,timeout=180,check=True)
        log=(a.out/(label+'.log')).read_text()
        if 'D27_CURRENT_SEED_PASS' not in log:raise ValueError('Private seed guest did not complete: '+label)
        return log
    body=''
    for name in prefs:
        body+=f'echo PREF_BEGIN_{name}\nif [ -f /mnt/data/mobile/Library/Preferences/{name}.plist ]; then base64 /mnt/data/mobile/Library/Preferences/{name}.plist; fi\necho PREF_END_{name}\n'
    log=linux_run(body,'read')
    import base64
    merged={}
    for name,values in prefs.items():
        encoded=log.split('PREF_BEGIN_'+name+'\n',1)[1].split('PREF_END_'+name,1)[0].strip()
        data=plistlib.loads(base64.b64decode(encoded)) if encoded else {}
        if not isinstance(data,dict):raise ValueError('Existing preference is not a dictionary')
        merged[name]=dict(data);data.update(values)
        (initramfs/'payload'/(name+'.plist')).write_bytes(plistlib.dumps(data,fmt=plistlib.FMT_XML))
    body='mkdir -p /mnt/data/mobile/Library/Preferences\n'
    for name in prefs:body+=f'cp /payload/{name}.plist /mnt/data/mobile/Library/Preferences/{name}.plist\nchown 501:501 /mnt/data/mobile/Library/Preferences/{name}.plist\nchmod 600 /mnt/data/mobile/Library/Preferences/{name}.plist\n'
    body+='chown 501:501 /mnt/data/mobile /mnt/data/mobile/Library /mnt/data/mobile/Library/Preferences\n'
    body+='for d in Bundle Data/System Shared/SystemGroup Temp; do mkdir -p /mnt/data/containers/$d; chmod 755 /mnt/data/containers/$d; done\n'
    body+='stat -c "%u:%g %n" /mnt/data/mobile/Library/Preferences/*.plist\n'
    linux_run(body,'write')
    with (a.out/'apfsck.log').open('x') as f:subprocess.run([inputs['apfsck'],str(raw)],stdout=f,stderr=subprocess.STDOUT,check=True)
    packed_ramdisk.pack(raw,a.out/'scratch-data.img')
    result=dict(original_seed_sha256=sha(original),private_seed_sha256=sha(a.out/'scratch-data.img'),logical_bytes=logical,
                preferences_added=prefs,original_preferences=merged,uid=501,gid=501,build='24A446',
                original_seed_unchanged=sha(original)=='23cd7aa2db7b26eae5d30b956d840f475c45017893077005a8b8ce87e44b584d',device_operations=False)
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)

if __name__=='__main__':main()
