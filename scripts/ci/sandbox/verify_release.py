#!/usr/bin/env python3
"""Independent unpack/verify of a PDX234 dual boot image against the 010 baseline."""
import hashlib, hmac, lzma, struct, sys, zlib
sys.path.insert(0, '/sessions/youthful-great-ramanujan/tools')
from fatfs import Fat
from macho import MachO
sha = lambda b: hashlib.sha256(b).hexdigest()

def unpack(path):
    img = open(path, 'rb').read()
    assert img[:8] == b'ANDROID!' and struct.unpack_from('<I', img, 40)[0] == 4
    ksz = struct.unpack_from('<I', img, 8)[0]
    comb = img[4096:4096 + ksz]
    meta = struct.unpack('<8sIIQQQIIQQQQ', comb[-80:])
    assert meta[0] == b'PXCBHOF1'
    bundle = comb[meta[10]:meta[10] + meta[11]]
    mg, hs, cl, rl, crc, res = struct.unpack_from('<8s4IQ', bundle)
    s = bytearray(bundle[32:]); declared = struct.unpack_from('<Q', s, 5)[0]; s[5:13] = b'\xff' * 8
    fat = lzma.decompress(bytes(s), format=lzma.FORMAT_ALONE)
    assert mg == b'PDXFAT02' and len(fat) == rl == declared and zlib.crc32(fat) == crc and cl == len(bundle) - 32
    f = Fat(bytearray(fat))
    files = {p: f.read('EFI/UniXNU/' + p) for p in ('unixnu.toml', 'Payloads/kernel.macho', 'Payloads/kernel.macho.adt',
             'Payloads/kernel.macho.trustcache', 'Payloads/kernel.macho.vroot', 'Payloads/scratch-data.img')}
    android = comb[0x200000:0x200000 + meta[4]]
    mem = struct.unpack_from('<Q', android, 16)[0]
    fd = comb[0x200000 + mem:0x200000 + mem + 0x300000]
    return dict(img=img, header=img[:4096], comb=comb, meta=meta, android=android, fd=fd, files=files, ksz=ksz)

def seal_ok(k):
    m = MachO(k)
    ke = next(e for e in m.entries if e['name'] == 'com.apple.kernel')
    km = MachO(k, ke['fileoff'])
    text = next(s for s in next(sg for sg in km.segments if sg['name'] == '__TEXT_EXEC')['sects'] if s['sect'] == '__text')
    fips = [s for sg in km.segments for s in sg['sects'] if s['sect'] == '__fips_hmacs'][0]
    mac = hmac.digest(b'\0', k[text['offset']:text['offset'] + text['size']], 'sha256')
    return mac == k[fips['offset']:fips['offset'] + 32], mac.hex()

a = unpack(sys.argv[1]); b = unpack(sys.argv[2])
print('base', sys.argv[1].split('/')[-1], sha(a['img'])[:16], ' new', sys.argv[2].split('/')[-1], sha(b['img'])[:16])
print('android identical:', a['android'] == b['android'], sha(b['android'])[:16])
print('FD identical:', a['fd'] == b['fd'], sha(b['fd'])[:16])
print('boot header diff bytes:', [i for i in range(4096) if a['header'][i] != b['header'][i]])
for p in a['files']:
    print('  %-32s same=%s  sha=%s' % (p, a['files'][p] == b['files'][p], sha(b['files'][p])[:16]))
ka, kb = a['files']['Payloads/kernel.macho'], b['files']['Payloads/kernel.macho']
if len(ka) == len(kb):
    d = [i for i in range(0, len(ka), 4) if ka[i:i + 4] != kb[i:i + 4]]
    print('kernel differing words:', len(d), [hex(x) for x in d[:12]])
print('seal base:', seal_ok(ka)[0], ' seal new:', seal_ok(kb))
print('menu:', [l for l in b['files']['unixnu.toml'].decode().splitlines() if 'title' in l][0])
print('args:', [l for l in b['files']['unixnu.toml'].decode().splitlines() if l.startswith('args')][0])
