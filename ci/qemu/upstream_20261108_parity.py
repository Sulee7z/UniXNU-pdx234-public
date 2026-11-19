"""Exact late generic arm64e/VFS patch hunks missing from the pinned profile."""
from pathlib import Path
import difflib
import hashlib

ROOT=Path(__file__).resolve().parents[2]/'patches/upstream-parity'
PINS={
    'native-pac-arm64-user-jop.patch':'09904a9e97a5f5885bb65a7adcb087aea133d1308f5f10da386c729973fef8e2',
    'native-at-par-sync.patch':'ba976042976864629d65b5e38d661fb4c52f1c5ad2840dc723de52eaf506556d',
    'native-union-statfs-fsid.patch':'1b2eb155c705d77bcbaed8bb322fb90428704e15c0cb5ffe12313942c95a9161',
}
COMMITS={
    'native-pac-arm64-user-jop.patch':'bbf9bd7347def4ff6169ffc26b39767ced84125e',
    'native-at-par-sync.patch':'d6f1eff1db02be60680be44018681fc434c82cd4',
    'native-union-statfs-fsid.patch':'6ab05d46a02984131492fd818c174484a07fa7f8',
}
FILES={'osfmk/arm64/locore.s':'locore.s','osfmk/arm64/machine_routines_asm.s':'machine_routines_asm.s',
       'bsd/vfs/vfs_syscalls.c':'vfs_syscalls.c'}


def parse(patch):
    changes=[];current=None;lines=patch.splitlines(True);i=0
    while i<len(lines):
        line=lines[i]
        if line.startswith('+++ b/'):current=line[6:].strip()
        if not line.startswith('@@'):
            i+=1;continue
        old=[];new=[];i+=1
        while i<len(lines) and not lines[i].startswith(('@@','diff --git ')):
            row=lines[i]
            if row.startswith('--- '):break
            if row.startswith(' '):old.append(row[1:]);new.append(row[1:])
            elif row.startswith('-'):old.append(row[1:])
            elif row.startswith('+'):new.append(row[1:])
            elif row.startswith('\\'):
                pass
            else:
                break
            i+=1
        changes.append((current,''.join(old),''.join(new)))
    return changes


def adapt(unit,text):
    selected=[]
    for name in PINS:
        path=ROOT/name;raw=path.read_text().encode()
        if hashlib.sha256(raw).hexdigest()!=PINS[name]:raise ValueError('Pinned upstream patch SHA changed: '+name)
        for target,old,new in parse(raw.decode()):
            if target==unit:selected.append((name,old,new))
    if not selected:raise ValueError('No pinned upstream hunk for '+unit)
    for name,old,new in selected:
        if not old or text.count(old)!=1:raise ValueError('Upstream hunk context is not unique: '+name+' '+unit)
        text=text.replace(old,new,1)
    return text


def locore(text):return adapt('osfmk/arm64/locore.s',text)


def machine_routines(text):return adapt('osfmk/arm64/machine_routines_asm.s',text)


def readdir_and_statfs(text):
    from upstream_startup import readdir
    return adapt('bsd/vfs/vfs_syscalls.c',readdir(text))


ADAPTERS={'official-upstream-parity:locore.s':locore,
          'official-upstream-parity:machine_routines_asm.s':machine_routines,
          'upstream-union-readdir':readdir_and_statfs}


def make_diff(path,before,after):
    return ''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),
        fromfile='a/'+path,tofile='b/'+path))
