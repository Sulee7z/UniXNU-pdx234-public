"""Qualified Sony SSUsb1InitCommon preparation error propagation.

UsbConfigUsbCores.c SHA256 79c606c4d788e481c5781f6d47e5c8c9deb768bff52e34b3ec7c311f7f3336f1:
lines 403-421 return EFI_INVALID_PARAMETER for a null rail client; lines
570-615 define ConfigPowerDomain as EFI_STATUS (documenting EFI_NOT_FOUND
for absent ClockProtocol). Lines 1514, 1529-1534, 1579-1581 discard these
failures. Preserve the actual EFI status and stop this preparation attempt.
Also stop ConfigPowerDomain after its failed ID lookup (line 592) before
consuming an uninitialized domain ID and overwriting the first error.

Other WRN_CHK sites retain their continue policy; SS PHY failure still falls
back to HS. usb_shared_hs_phy_init's declaration is not
in this source fixture: its x0 is NOT treated as a status or boolean.
No rail/clock/reset sequence changes on the successful path; no new cleanup.
"""
import hashlib
import struct
from pathlib import Path
import subprocess
import tempfile

ORIGINAL_SHA = 'b87b97a843fe8bc53e803a169ca7549246921aa2a4c1f291c6ad4843a58a87b9'
SOURCE_SHA = '79c606c4d788e481c5781f6d47e5c8c9deb768bff52e34b3ec7c311f7f3336f1'
BASE = 0x14d00
END = 0x14d74
# Post-call instructions, replayed exactly when EFI_ERROR(x0) is false.
CHECKS = {
    0x954c: 'a1c35cb8',  # rail SS: ldur w1,[x29,#-0x34]
    0x955c: '01000014',  # rail HS: b next
    0x9570: '68000090',  # GDSC first: adrp x8,0x15000
    0x971c: '68000090',  # GDSC second: adrp x8,0x15000
    0x9748: 'e82740f9',  # GDSC third: ldr x8,[sp,#0x48]
}
CALLS = {0x9548: 0x87c0, 0x9558: 0x87c0, 0x956c: 0xad00,
         0x9718: 0xad00, 0x9744: 0xad00}
TRACE_BASE = 0x14d80
TRACE_COUNTER = 0x15ff0
TRACE_LIMIT = 64
TRACE_CALLS = {**CALLS, 0x9534: 0xe6b8, 0x9594: 0xe99c,
               0x95e0: 0x84c0, 0x963c: 0x8650, 0x96a8: 0x84c0,
               0x9760: 0x8990, 0x9768: 0x8b00, 0x97c4: 0xaf00,
               0x8c1c: 0xea1c}


def branch(source, target, link=False):
    delta = target - source
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError('Invalid AArch64 branch')
    return struct.pack('<I', (0x94000000 if link else 0x14000000) |
                       ((delta // 4) & 0x3ffffff))


def adapt_pe(raw, trace=False):
    """Return adapted bytes from the original PE only; rejects composed inputs.

    trace=True additionally requires clang, ld.lld and llvm-objcopy and adds
    at most 64 entry/return pairs per image at the listed preparation sites.
    """
    if hashlib.sha256(raw).hexdigest() != ORIGINAL_SHA:
        raise ValueError('Unknown Sony UsbConfig executable')
    nt = struct.unpack_from('<I', raw, 60)[0]
    section = nt + 24 + struct.unpack_from('<H', raw, nt + 20)[0]
    if (raw[section:section + 8] != b'.text\0\0\0' or
            struct.unpack_from('<4I', raw, section + 8) !=
            (0x14000, 0x1000, 0x14000, 0x1000) or
            struct.unpack_from('<I', raw, section + 36)[0] != 0x60000020):
        raise ValueError('Unexpected UsbConfig executable mapping')
    if raw[BASE:END] != bytes(END - BASE):
        raise ValueError('Preparation error cave occupied')
    for site, target in CALLS.items():
        if raw[site:site + 4] != branch(site, target, True):
            raise ValueError('Preparation call changed: ' + hex(site))
    if raw[0x94a4:0x94a8] != branch(0x94a4, 0x9a1c):
        raise ValueError('ClockProtocol error path changed')
    if raw[0xad84:0xad88] != branch(0xad84, 0xad88):
        raise ValueError('Power-domain lookup error path changed')
    result = bytearray(raw)
    # Do not use the uninitialized domain ID or overwrite the first error
    # when GetClockPowerDomainID fails. Keep its existing warning diagnostic.
    result[0xad84:0xad88] = branch(0xad84, 0xaedc)
    # Missing ClockProtocol: Status = EFI_NOT_FOUND; original ON_EXIT.
    blob = struct.pack('<III', 0xd28001c8, 0xf2f00008, 0xf81e83a8)
    blob += branch(BASE + 12, 0x9a1c)
    result[0x94a4:0x94a8] = branch(0x94a4, BASE)
    for site, expected in CHECKS.items():
        original = bytes.fromhex(expected)
        if raw[site:site + 4] != original:
            raise ValueError('Preparation continuation changed: ' + hex(site))
        stub = BASE + len(blob)
        result[site:site + 4] = branch(site, stub)
        # tbz x0,#63,success; Status=x0; b ON_EXIT; replay; b continuation.
        blob += struct.pack('<II', 0xb6f80060, 0xf81e83a0)
        blob += branch(stub + 8, 0x9a1c)
        if site in (0x9570, 0x971c):
            original = struct.pack('<I', 0xb0000008)  # adrp x8,0x15000
        elif site == 0x955c:
            original = branch(stub + 12, site + 4)
        blob += original + branch(stub + 16, site + 4)
    if len(blob) != END - BASE:
        raise ValueError('Incorrect preparation stub size')
    result[BASE:END] = blob
    if trace:
        with tempfile.TemporaryDirectory(prefix='sony-prepare-') as directory:
            work = Path(directory)
            text = Path(__file__).with_suffix('.S').read_text()
            wrappers = '\n'.join('WRAPPER Trace_%x, 0x%x, Target_%x' % (s, s, t)
                                 for s, t in sorted(TRACE_CALLS.items()))
            (work / 'trace.S').write_text(text.replace('// WRAPPERS', wrappers))
            subprocess.run(['clang', '--target=aarch64-none-elf', '-c', str(work / 'trace.S'),
                            '-o', str(work / 'trace.o')], check=True)
            command = ['ld.lld', '-Ttext=' + hex(TRACE_BASE), '-e', 'PrepareTrace',
                       str(work / 'trace.o'), '-o', str(work / 'trace.elf'),
                       '--defsym=DebugPrint=0x1d0c', '--defsym=Counter=' + hex(TRACE_COUNTER)]
            command += ['--defsym=Target_%x=0x%x' % (t, t) for t in sorted(set(TRACE_CALLS.values()))]
            subprocess.run(command, check=True)
            subprocess.run(['llvm-objcopy', '--only-section=.text', '-O', 'binary',
                            str(work / 'trace.elf'), str(work / 'trace.bin')], check=True)
            code = (work / 'trace.bin').read_bytes()
        if TRACE_BASE + len(code) > 0x15000 or raw[TRACE_BASE:TRACE_BASE + len(code)] != bytes(len(code)):
            raise ValueError('Preparation trace cave occupied or too small')
        if raw[TRACE_COUNTER:TRACE_COUNTER + 4] != bytes(4):
            raise ValueError('Preparation trace counter occupied')
        result[TRACE_BASE:TRACE_BASE + len(code)] = code
        for index, (site, target) in enumerate(sorted(TRACE_CALLS.items())):
            if raw[site:site + 4] != branch(site, target, True):
                raise ValueError('Preparation trace call changed: ' + hex(site))
            result[site:site + 4] = branch(site, TRACE_BASE + index * 12, True)
    return bytes(result)
