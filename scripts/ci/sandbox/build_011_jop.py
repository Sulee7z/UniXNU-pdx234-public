#!/usr/bin/env python3
"""PAC-ABI-011: 010 + upstream native default-JOP policy (ml_default_jop_pid returns 1).

The source change (UniXNU a11553a7 native-pac-keys.patch hunk) compiles to one word in the
isolated 8-byte function _ml_default_jop_pid (MOV X0,#0 -> MOV W0,#1); every user calls it
through BL, so writing that word is byte-identical to recompiling machine_routines_apple.c.
The POST HMAC is recomputed with the official seal script; nothing else changes.
"""
import hashlib, hmac, json, lzma, os, shutil, struct, subprocess, sys, zlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from macho import MachO
from fatfs import Fat

W = Path('/sessions/youthful-great-ramanujan/work')
IN = W / 'in010'
OUT = W / 'r011'
BOOT010 = Path('/sessions/youthful-great-ramanujan/mnt/e/UniXNU-Port-artifacts/storage-recovery-20261114-001/d27-pac-abi-release-20261114-010/boot-pdx234-pac-abi-010.img')
SEAL = W / 'unixnu-scripts/seal-source-crypto-kernel.py'
SHIM = Path('/sessions/youthful-great-ramanujan/mnt/g/UniXNU-Port/ports/uefi-pdx234/BootShim/Pdx234Combo.S')
EXPECT = dict(kernel='c139ed264a0ab216b8ea8725d6c31ecf692ded015962ba3bddaf2aded8fb9c5c',
              native='bc6a76fdfa523bd4bc632af41c9e0145c42226fedae83d8c5aa99a4b05445f96',
              fat='8ca070dadb7037bd1550dc331228713ceaf4b52a63a16abdaa865ffc13917383',
              bundle='5f8847c733912a02a1241da21a131ba04e08f2d0ec7edf5f830d2252dfa7fc7d',
              boot='161f9bf14ec2ddf7cbe33e49b8629478e1e07e2cb09efe26912382391c5ffae5',
              android='92321cba44b4d5f32355e694ed918125b8e56810ff2580b7a904cef0f719549f')
OLD_WORD, NEW_WORD = 0xD2800000, 0x52800020   # mov x0,#0  ->  mov w0,#1
KARGS010 = '-v serial=3 debug=0x14e kt_fixed_zones=120 -no_slto_panic use_contiguous_hint=0 native-source-storage=1 native-ufs-root=1 data-persist=0 log=1 log-reserve=1024 autoreset=180'
# sheng iPadOS 27 default userland policy (board.toml kernel_args) that this kernel implements:
# no-lc=1 is spelled sheng-no-lc on the 82b847c4 core this kernel was built from.
SHENG_POLICY = ['sheng-no-lc=1', 'disable-watchdogd=1', 'lite=1']
KARGS = KARGS010 + ' ' + ' '.join(SHENG_POLICY)
sha = lambda b: hashlib.sha256(b).hexdigest()

def lzma_alone_decode(stream):
    """Decode .lzma with a known size and an end marker. Ubuntu 22.04's liblzma 5.2 rejects
    that combination (5.4+ accepts it), so verify through the unknown-size form of the same stream
    and then require the decoded length to equal the declared size."""
    declared = struct.unpack_from('<Q', stream, 5)[0]
    probe = bytearray(stream); probe[5:13] = b'\xff' * 8
    out = lzma.decompress(bytes(probe), format=lzma.FORMAT_ALONE)
    need(len(out) == declared, 'LZMA declared size')
    return out

def need(cond, msg):
    if not cond:
        raise SystemExit('REFUSED: ' + msg)

def main():
    OUT.mkdir(parents=True, exist_ok=False)
    kernel = bytearray((W / 'k010/payload-kernel.macho').read_bytes())
    native = (W / 'k010/native.macho').read_bytes()
    fat_img = bytearray((IN / 'payload.fat').read_bytes())
    bundle_old = (IN / 'payload.bundle').read_bytes()
    boot_old = BOOT010.read_bytes()
    for name, data in (('kernel', kernel), ('native', native), ('fat', fat_img), ('bundle', bundle_old), ('boot', boot_old)):
        need(sha(data) == EXPECT[name], name + ' input identity')

    # 1. locate _ml_default_jop_pid: native symbol -> fileset com.apple.kernel __TEXT_EXEC
    n = MachO(native); syms = n.symbols()
    nte = next(s for s in n.segments if s['name'] == '__TEXT_EXEC')
    fs = MachO(bytes(kernel))
    ke = next(e for e in fs.entries if e['name'] == 'com.apple.kernel')
    k = MachO(bytes(kernel), ke['fileoff'])
    kte = next(s for s in k.segments if s['name'] == '__TEXT_EXEC')
    need(nte['vmsize'] == kte['vmsize'] and nte['filesize'] == kte['filesize'], 'kernel text placement')
    rel = syms['_ml_default_jop_pid'] - nte['vmaddr']
    site = kte['fileoff'] + rel
    site_va = kte['vmaddr'] + rel
    # the whole native text must be identical to the fileset copy except the two panic hooks region
    ntext = native[nte['fileoff']:nte['fileoff'] + nte['filesize']]
    ktext = bytes(kernel[kte['fileoff']:kte['fileoff'] + kte['filesize']])
    need(ntext[rel - 0x14:rel + 0x10] == ktext[rel - 0x14:rel + 0x10], 'fileset copy of machine_routines_apple text')
    expect_fn = struct.pack('<9I', 0xD65F03C0, 0xD65F03C0, 0xD65F03C0, 0xD2800000, 0xD65F03C0,
                            0xD2800000, 0xD65F03C0, 0xD2800000, 0xD65F03C0)
    need(bytes(kernel[site - 0x14:site + 0x10]) == expect_fn, 'machine_routines_apple function bodies')
    # 2. HMAC sanity before patching (my model of the seal must reproduce the stored value)
    seal010 = json.loads((W / 'base/payload-pac-abi-010__kernel.macho.crypto-hmac.json').read_text())
    co, cn, ho = int(seal010['code_file_offset'], 16), seal010['code_bytes'], int(seal010['hmac_file_offset'], 16)
    need(hmac.digest(b'\0', bytes(kernel[co:co + cn]), 'sha256') == bytes(kernel[ho:ho + 32]), '010 POST HMAC model')
    need(co <= site < co + cn, 'site inside the sealed code range (reseal required)')
    struct.pack_into('<I', kernel, site, NEW_WORD)
    kpath = OUT / 'kernel.macho'
    kpath.write_bytes(kernel)
    env = dict(os.environ, UNIXNU_XNU_ARCH='arm64e', UNIXNU_IOS_VERSION='27.0')
    subprocess.run([sys.executable, '-I', str(SEAL), str(kpath), '--kernel-args', KARGS], check=True, env=env,
                   cwd=str(SEAL.parent)) if False else subprocess.run(
                   [sys.executable, str(SEAL), str(kpath), '--kernel-args', KARGS], check=True, env=env, cwd=str(SEAL.parent))
    sealed = kpath.read_bytes()
    orig = (W / 'k010/payload-kernel.macho').read_bytes()
    diffs = [i for i in range(0, len(orig), 4) if orig[i:i + 4] != sealed[i:i + 4]]
    in_hmac = [i for i in diffs if ho - 4 < i < ho + 32]
    need(len(sealed) == len(orig) and site in diffs and set(diffs) - set(in_hmac) == {site}, 'only JOP word + HMAC changed')
    seal011 = json.loads((OUT / 'kernel.macho.crypto-hmac.json').read_text())
    need(seal011['code_file_offset'] == seal010['code_file_offset'] and seal011['code_bytes'] == cn, 'seal range')

    # 3. FAT: overwrite kernel + relabel menu in place (sizes unchanged)
    fat = Fat(fat_img)
    toml = fat.read('EFI/UniXNU/unixnu.toml').decode()
    need(toml.count('PAC-ABI-010 PANIC SCREEN') == 1 and toml.count('args = "' + KARGS010 + '"') == 1, 'menu label/args')
    fat.overwrite('EFI/UniXNU/Payloads/kernel.macho', sealed)
    toml = toml.replace('PAC-ABI-010 PANIC SCREEN', 'PAC-ABI-011 PANIC SCREEN').replace('args = "' + KARGS010 + '"', 'args = "' + KARGS + '"')
    need(len(KARGS) <= 1000, 'command line limit')
    fat.overwrite_resized('EFI/UniXNU/unixnu.toml', toml.encode())
    need(Fat(fat_img).read('EFI/UniXNU/unixnu.toml') == toml.encode(), 'toml readback')
    check = Fat(fat_img)
    need(check.read('EFI/UniXNU/Payloads/kernel.macho') == sealed, 'FAT kernel readback')
    for other in ('kernel.macho.adt', 'kernel.macho.trustcache', 'kernel.macho.vroot', 'scratch-data.img'):
        need(check.read('EFI/UniXNU/Payloads/' + other) == Fat(bytearray((IN / 'payload.fat').read_bytes())).read('EFI/UniXNU/Payloads/' + other), other)
    raw = bytes(fat_img)
    (OUT / 'payload.fat').write_bytes(raw)

    # 4. PDXFAT02 bundle exactly as release-d27-pac-abi.py
    comp = bytearray(lzma.compress(raw, format=lzma.FORMAT_ALONE, preset=6))
    comp[5:13] = struct.pack('<Q', len(raw))
    need(lzma_alone_decode(bytes(comp)) == raw, 'LZMA roundtrip')
    bundle = struct.pack('<8s4IQ', b'PDXFAT02', 32, len(comp), len(raw), zlib.crc32(raw), 0) + bytes(comp)
    (OUT / 'payload.bundle').write_bytes(bundle)

    # 5. combo Image: rebuild from the official BootShim source with the same inputs (zig clang/lld)
    bsz = struct.unpack_from('<I', boot_old, 8)[0]
    combined_old = boot_old[4096:4096 + bsz]
    meta = struct.unpack('<8sIIQQQIIQQQQ', combined_old[-80:])
    off_old, len_old = meta[10], meta[11]
    need(combined_old[off_old:off_old + len_old] == bundle_old, '010 bundle placement')
    android = combined_old[0x200000:0x200000 + 50964992]
    need(sha(android) == EXPECT['android'], 'Android image identity')
    memory_size, flags = struct.unpack_from('<QQ', android, 16)
    fd = combined_old[0x200000 + memory_size:0x200000 + memory_size + 0x300000]
    build = OUT / 'combo'; build.mkdir()
    (build / 'android.Image').write_bytes(android); (build / 'fd.bin').write_bytes(fd)
    (build / 'Pdx234ComboInputs.h').write_text('\n'.join([
        f'#define ANDROID_INPUT_PATH "{build / "android.Image"}"',
        f'#define UEFI_FD_INPUT_PATH "{build / "fd.bin"}"',
        f'#define XNU_BUNDLE_INPUT_PATH "{OUT / "payload.bundle"}"',
        f'#define ANDROID_MEMORY_BYTES {memory_size}', f'#define ANDROID_IMAGE_FLAGS {flags}',
        f'#define ANDROID_IMAGE_BYTES {len(android)}', f'#define ANDROID_IMAGE_CRC32 {zlib.crc32(android)}',
        '#define ANDROID_PAYLOAD_OFFSET 0x200000', '#define SPMI_CORE_BASE 0xc400000',
        '#define SPMI_OBSERVER_BASE 0xc440000', '#define FD_BASE 0xa7100000', '#define FD_SIZE 0x300000']) + '\n')
    shutil.copyfile(SHIM, build / 'Pdx234Combo.S')
    zig = [sys.executable, '-m', 'ziglang']
    subprocess.run(zig + ['cc', '--target=aarch64-freestanding-none', '-I', str(build), '-c', str(build / 'Pdx234Combo.S'), '-o', str(build / 'combo.o')], check=True)
    subprocess.run(zig + ['ld.lld', '--image-base=0', '-Ttext=0', '-e', '_Head', str(build / 'combo.o'), '-o', str(build / 'combo.elf')], check=True)
    subprocess.run(zig + ['objcopy', '-O', 'binary', str(build / 'combo.elf'), str(build / 'combo.Image')], check=True)
    combined = (build / 'combo.Image').read_bytes()
    # reconstruction check: identical to 010 except the bundle, its length and the image-size constants
    m = struct.unpack('<8sIIQQQIIQQQQ', combined[-80:])
    need(m[:10] == meta[:10] and m[10] == off_old and m[11] == len(bundle), 'BootShim metadata')
    # Allowed stub differences: the two image-size quads (header + literal) and the lo12 of the
    # ADRP/ADD pair that addresses the trailing metadata (it moves with the bundle length).
    words = [i for i in range(0, off_old, 4) if combined[i:i + 4] != combined_old[i:i + 4]]
    size_q = [i for i in range(0, 0x1000, 8) if combined_old[i:i + 8] == struct.pack('<Q', len(combined_old))]
    allowed = set(size_q)
    meta_old, meta_new = len(combined_old) - 80, len(combined) - 80
    need(meta_old >> 12 == meta_new >> 12, 'metadata stays in the same ADRP page')
    for i in words:
        if i in allowed:
            need(combined[i:i + 8] == struct.pack('<Q', len(combined)), 'image size constant')
            continue
        a, b = struct.unpack_from('<I', combined_old, i)[0], struct.unpack_from('<I', combined, i)[0]
        need(i < 0x1000 and a & 0xFFC003FF == b & 0xFFC003FF and (a & 0xFF000000) == 0x91000000 and
             (a >> 10) & 0xFFF == meta_old & 0xFFF and (b >> 10) & 0xFFF == meta_new & 0xFFF, 'metadata ADD lo12 at %#x' % i)
    need(combined[0x1000:off_old] == combined_old[0x1000:off_old], 'Android/FD bytes')
    need(combined[off_old:off_old + len(bundle)] == bundle, 'bundle bytes in combo')
    need(struct.unpack_from('<QQQ', combined, 8) == (0, len(combined), flags), 'Image header')
    # 6. boot v4 image: 010 header with the new kernel size
    header = bytearray(boot_old[:4096])
    struct.pack_into('<I', header, 8, len(combined))
    image = bytes(header) + combined + bytes(-len(combined) % 4096)
    need(len(image) <= 100663296, 'boot partition capacity')
    final = OUT / 'boot-pdx234-pac-abi-011.img'
    final.write_bytes(image)
    # 7. independent unpack
    u = final.read_bytes()
    field = u[4096:4096 + struct.unpack_from('<I', u, 8)[0]]
    mm = struct.unpack('<8sIIQQQIIQQQQ', field[-80:])
    b2 = field[mm[10]:mm[10] + mm[11]]
    mg, hs, cl, rl, crc, _ = struct.unpack_from('<8s4IQ', b2)
    fat2 = lzma_alone_decode(b2[32:])
    need(mg == b'PDXFAT02' and len(fat2) == rl and zlib.crc32(fat2) == crc, 'bundle unpack')
    k2 = Fat(bytearray(fat2)).read('EFI/UniXNU/Payloads/kernel.macho')
    need(k2 == sealed and struct.unpack_from('<I', k2, site)[0] == NEW_WORD, 'unpacked kernel')
    need(sha(field[0x200000:0x200000 + len(android)]) == EXPECT['android'], 'unpacked Android')
    need(field[0x200000 + memory_size:0x200000 + memory_size + 0x300000] == fd, 'unpacked FD')
    rep = dict(label='PAC-ABI-011', added_kernel_args=SHENG_POLICY, image=final.name, bytes=len(image), sha256=sha(image),
               base_release='PAC-ABI-010 161f9bf1', change='upstream native default JOP policy: _ml_default_jop_pid returns 1',
               upstream='UniXNU/UniXNU a11553a7 patches/xnu-12377/native-pac-keys.patch',
               site_va=hex(site_va), site_file_offset=hex(site), old_word=hex(OLD_WORD), new_word=hex(NEW_WORD),
               callers=['_task_init', '_shared_region_key_alloc', '_cpu_data_init', '_ml_task_set_jop_pid', '_arm_init'],
               payload_kernel_sha256=sha(sealed), post_hmac=seal011['hmac_sha256'], fat_sha256=sha(raw),
               bundle_sha256=sha(bundle), bundle_bytes=len(bundle), combo_sha256=sha(combined),
               android_sha256=EXPECT['android'], kernel_args=KARGS, adt_unchanged=True, panic_screen=True,
               pac_enabled=True, auth_instruction_patches=False, device_writes=False, hardware_boot_verified=False)
    (OUT / 'release.json').write_text(json.dumps(rep, indent=2) + '\n')
    (OUT / 'SHA256SUMS').write_text(f"{rep['sha256']}  {final.name}\n")
    print(json.dumps(rep, indent=2))

main()
