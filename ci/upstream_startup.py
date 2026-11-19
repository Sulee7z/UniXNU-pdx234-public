"""Replay pinned shared upstream source hunks without modifying the base tree."""
from pathlib import Path
import difflib
import hashlib
import re

ROOT = Path(__file__).resolve().parents[1] / 'patches/upstream-startup'
HASHES = {
    'native-4k-shared-region-slide.patch': '076be2859a0a7cf31574995c4a985da13f7b914ec55724eb82ae11a19b800b13',
    'native-union-readdir-eof.patch': '764075e4cb2d9905e6e9488cf1ad9d3bb9c958eca06bd454d7de2afc4354e136',
    'native-modload-lock-order.patch': '3e0ab6401a83d43599d6b35abd211da2bc7d988834cd9e6521dd46ebe1c1bfe5',
    'baseline-shared-region-slide.patch': '08b1ce81df07619bada0d128fd4a5f87d697d7dbade757bc218fd92d26087ac8',
}


def read_patch(name):
    data = (ROOT / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != HASHES[name]:
        raise ValueError('Upstream input changed: ' + name)
    return data.decode()


def replace_once(text, old, new):
    if not old or text.count(old) != 1:
        raise ValueError('Upstream source context is not unique')
    return text.replace(old, new, 1)


def apply_hunks(text, patch_name, target):
    lines = read_patch(patch_name).splitlines(True)
    i, current, applied = 0, None, 0
    while i < len(lines):
        if lines[i].startswith('+++ b/'):
            current = lines[i][6:].strip()
        match = re.match(r'@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@', lines[i])
        if not match:
            i += 1
            continue
        old_left, new_left = (int(v) if v is not None else 1 for v in match.groups())
        old, new = [], []
        i += 1
        while old_left or new_left:
            line = lines[i]
            if line[0] in ' -':
                old.append(line[1:]); old_left -= 1
            if line[0] in ' +':
                new.append(line[1:]); new_left -= 1
            if line[0] not in ' +- ' or old_left < 0 or new_left < 0:
                raise ValueError('Malformed upstream hunk')
            i += 1
        if current == target:
            text = replace_once(text, ''.join(old), ''.join(new))
            applied += 1
    if not applied:
        raise ValueError('No selected upstream source hunks')
    return text


def pager(text):
    # Both published patch versions have the same existing added code. Reuse
    # only their three insertion deltas, including surrounding exact C context.
    def additions(name):
        return [l[1:] for l in read_patch(name).splitlines(True)
                if l.startswith('+') and not l.startswith('+++')]
    old = additions('baseline-shared-region-slide.patch')
    new = additions('native-4k-shared-region-slide.patch')
    count = 0
    for tag, a, z, c, e in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag == 'equal':
            continue
        if tag != 'insert':
            raise ValueError('Unexpected pager delta')
        before, after = ''.join(old[a-2:a]), ''.join(old[a:a+2])
        text = replace_once(text, before + after, before + ''.join(new[c:e]) + after)
        count += 1
    if count != 3:
        raise ValueError('Expected three published pager insertions')
    return text


def readdir(text):
    return apply_hunks(text, 'native-union-readdir-eof.patch', 'bsd/vfs/vfs_syscalls.c')


def metaclass(text):
    return apply_hunks(text, 'native-modload-lock-order.patch', 'libkern/c++/OSMetaClass.cpp')


def kext(text):
    return apply_hunks(text, 'native-modload-lock-order.patch', 'libkern/c++/OSKext.cpp')


UNITS = {'vm_shared_region_pager.c': 'upstream-shared-region-release',
         'vfs_syscalls.c': 'upstream-union-readdir', 'OSMetaClass.cpp': 'upstream-modload-metaclass',
         'OSKext.cpp': 'upstream-modload-kext'}
ADAPTERS = dict(zip(UNITS.values(), (pager, readdir, metaclass, kext)))
