#!/usr/bin/env python3
"""Read-only access to the WSL ext4.vhdx (never writes)."""
import sys, os, stat
from dissect.hypervisor.disk.vhdx import VHDX
from dissect.extfs import ExtFS
from dissect.hypervisor.disk import vhdx as _V

# dissect.hypervisor bug: a read starting inside a 1 MiB payload block may run past the
# block's end into an unrelated file region. Split every read at payload-block boundaries.
_orig_read_sectors = _V.VHDX.read_sectors
def _read_sectors_split(self, sector, count):
    out = []
    while count > 0:
        in_block = sector % self._sectors_per_block
        n = min(count, self._sectors_per_block - in_block)
        out.append(_orig_read_sectors(self, sector, n))
        sector += n
        count -= n
    return b"".join(out)
_V.VHDX.read_sectors = _read_sectors_split

VHDX_PATH = '/sessions/youthful-great-ramanujan/mnt/g/UniXNU-Port/wsl/Ubuntu/ext4.vhdx'
_fs = None
def fs():
    global _fs
    if _fs is None:
        fh = open(VHDX_PATH, 'rb')
        disk = VHDX(fh)
        _fs = ExtFS(disk)
    return _fs

def ls(path):
    node = fs().get(path)
    for name, child in sorted(node.listdir().items()):
        if name in ('.', '..'): continue
        try:
            st = child.inode
            mode = child.filetype
            size = child.size
            print(f"{'d' if child.filetype==stat.S_IFDIR else ('l' if child.filetype==stat.S_IFLNK else '-')} {size:>14} {name}" + (f" -> {child.link}" if child.filetype==stat.S_IFLNK else ''))
        except Exception as e:
            print('?', name, e)

def cat(path, out=None):
    node = fs().get(path)
    fh = node.open()
    dst = open(out, 'wb') if out else sys.stdout.buffer
    while True:
        b = fh.read(1 << 20)
        if not b: break
        dst.write(b)
    if out: dst.close()

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'ls': ls(sys.argv[2])
    elif cmd == 'cat': cat(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
