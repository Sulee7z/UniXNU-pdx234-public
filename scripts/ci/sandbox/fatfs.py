"""Minimal read/patch access to a FAT12/16/32 image (no allocation changes)."""
import struct

class Fat:
    def __init__(self, data):
        self.d = data
        bps, spc, rsv, nfats, rootents, tot16, media, fatsz16, spt, heads, hidden, tot32 = struct.unpack_from('<HBHBHHBHHHII', data, 11)
        self.bps, self.spc, self.rsv, self.nfats, self.rootents = bps, spc, rsv, nfats, rootents
        fatsz = fatsz16 or struct.unpack_from('<I', data, 36)[0]
        tot = tot16 or tot32
        self.fatsz = fatsz
        self.rootsecs = (rootents * 32 + bps - 1) // bps
        self.first_data = rsv + nfats * fatsz + self.rootsecs
        clusters = (tot - self.first_data) // spc
        self.kind = 12 if clusters < 4085 else 16 if clusters < 65525 else 32
        self.root_cluster = struct.unpack_from('<I', data, 44)[0] if self.kind == 32 else None
        self.fat_off = rsv * bps
        self.csize = spc * bps

    def next(self, c):
        if self.kind == 32:
            return struct.unpack_from('<I', self.d, self.fat_off + c * 4)[0] & 0x0fffffff
        if self.kind == 16:
            return struct.unpack_from('<H', self.d, self.fat_off + c * 2)[0]
        v = struct.unpack_from('<H', self.d, self.fat_off + c * 3 // 2)[0]
        return v >> 4 if c & 1 else v & 0xfff

    def eoc(self, c):
        return c >= {12: 0xff8, 16: 0xfff8, 32: 0x0ffffff8}[self.kind]

    def chain(self, c):
        out = []
        while not self.eoc(c):
            if c < 2 or len(out) > 10_000_000:
                raise ValueError('bad cluster chain')
            out.append(c)
            c = self.next(c)
        return out

    def coff(self, c):
        return (self.first_data + (c - 2) * self.spc) * self.bps

    def dir_entries(self, cluster):
        if cluster is None:
            off = (self.rsv + self.nfats * self.fatsz) * self.bps
            raw = self.d[off:off + self.rootsecs * self.bps]
        else:
            raw = b''.join(self.d[self.coff(c):self.coff(c) + self.csize] for c in self.chain(cluster))
        lfn = []
        for i in range(0, len(raw), 32):
            e = raw[i:i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5:
                lfn = []
                continue
            if e[11] == 0x0F:
                part = e[1:11] + e[14:26] + e[28:32]
                lfn.insert(0, part.decode('utf-16le', 'ignore').split('\x00')[0].replace('￿', ''))
                continue
            short = e[0:8].decode('ascii', 'ignore').rstrip() + ('.' + e[8:11].decode('ascii', 'ignore').rstrip() if e[8:11].strip() else '')
            name = ''.join(lfn) or short
            lfn = []
            hi, lo = struct.unpack_from('<H', e, 20)[0], struct.unpack_from('<H', e, 26)[0]
            yield dict(name=name, attr=e[11], cluster=(hi << 16 | lo) if self.kind == 32 else lo,
                       size=struct.unpack_from('<I', e, 28)[0], dirent=self._dirent_offset(cluster, i))

    def _dirent_offset(self, cluster, i):
        if cluster is None:
            return (self.rsv + self.nfats * self.fatsz) * self.bps + i
        chain = self.chain(cluster)
        return self.coff(chain[i // self.csize]) + i % self.csize

    def overwrite_resized(self, path, content):
        """Replace a file whose new size keeps the same cluster count; updates the directory size."""
        e = self.lookup(path)
        clusters = self.chain(e['cluster'])
        need = (len(content) + self.csize - 1) // self.csize
        if need != len(clusters) or not content:
            raise ValueError('resize must keep the cluster count')
        for idx, c in enumerate(clusters):
            o = self.coff(c)
            chunk = content[idx * self.csize:(idx + 1) * self.csize]
            self.d[o:o + self.csize] = chunk + bytes(self.csize - len(chunk))
        struct.pack_into('<I', self.d, e['dirent'] + 28, len(content))

    def lookup(self, path):
        cluster = self.root_cluster
        parts = [p for p in path.split('/') if p]
        for idx, part in enumerate(parts):
            for e in self.dir_entries(cluster):
                if e['name'].lower() == part.lower():
                    if idx == len(parts) - 1:
                        return e
                    cluster = e['cluster']
                    break
            else:
                raise FileNotFoundError(path)

    def extents(self, entry):
        """(image_offset, length) runs covering the file's bytes."""
        runs, left = [], entry['size']
        for c in self.chain(entry['cluster']):
            n = min(left, self.csize)
            if n <= 0:
                break
            o = self.coff(c)
            if runs and runs[-1][0] + runs[-1][1] == o:
                runs[-1] = (runs[-1][0], runs[-1][1] + n)
            else:
                runs.append((o, n))
            left -= n
        return runs

    def read(self, path):
        e = self.lookup(path)
        return b''.join(bytes(self.d[o:o + n]) for o, n in self.extents(e))

    def overwrite(self, path, content):
        """Replace a file's bytes in place; size must not change."""
        e = self.lookup(path)
        if len(content) != e['size']:
            raise ValueError('in-place overwrite requires identical size')
        pos = 0
        for o, n in self.extents(e):
            self.d[o:o + n] = content[pos:pos + n]
            pos += n
