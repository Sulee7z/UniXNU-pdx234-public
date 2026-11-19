"""Propagate qualified Sony core-init failures through UsbfnEventHandler.

Composition: adapt_pe(original) or adapt_pe(core_errors.adapt_pe(original)).
Apply before the main-owned trace adaptation. Its call sites are untouched.
First failure returns the exact EFI core status and disables polling; later
polls return EFI_NOT_READY. Explicit driver shutdown remains possible. No
automatic retry, free, reset, or global/data latch is introduced.
"""
import hashlib
import struct
from sony_usb_core_errors import adapt_pe as fix_core, ORIGINAL_SHA, branch

BASE = 0x16f10
LIMIT = 0x17000
CORE_FIXED_SHA = '59af1c4bbfdf149db0c421dc9361c62c7e6cbf1c2fdee423c6a8336bddc14e8c'
SITES = {
    0x6380: ('CableFailure', 'f44f43a9'),
    0x62d8: ('Success', 'c0035fd6'),
    0x6300: ('LogSuccess', 'ac170014'),
    0x6498: ('PollReturn', '08000014'),
    0x64b8: ('PollSuccess', 'f30b40f9'),
    0x6410: ('LogFailure', '68170014'),
}
# EventHandler's empty-message path needs both Status and its queue-cleanup
# status register to retain the returned value. Public parameter checks and
# queued-message/buffer-too-small paths stay original.
MOVES = {0x2fa0: ('fa031faa', 0xaa0003fa),
         0x2fa4: ('f6031faa', 0xaa0003f6)}

# This is the exact output of sony_usb_poll_errors.S assembled with clang
# --target=aarch64-none-elf and linked at 0x16f10. Keeping the final bytes here
# makes the Windows PE verifier deterministic and compiler-free. The assembly
# remains the source of record; the machine-code test below checks the blob's
# entry points, bounds, and all call-site branches.
_PAYLOAD = bytes.fromhex(
    '7f020639e07bbfa9e30300aac1acfd70'
    '42a6fd700000b052a2d4ff97e07bc1a8'
    'f44f43a9f65742a9f70b40f9fd7bc4a8'
    'c0035fd6e0031faa1f0000f100409f9a'
    'f30b40f9fd7bc2a8c0035fd6fd7bbfa994'
    'd4ff97fd7bc1a8e0031faac0035fd6fd'
    '7bbfa98fd4ff97fd7bc1a8c00080d200'
    '00f0f2c0035fd6'
)
_SYMBOLS = {
    'CableFailure': 0x16f10, 'PollSuccess': 0x16f44,
    'PollReturn': 0x16f48, 'Success': 0x16f68,
    'LogSuccess': 0x16f5c, 'LogFailure': 0x16f70,
    'DebugPrint': 0xc1b0, 'FailureFormat': 0x124b7,
    'CableName': 0x123eb,
}

def payload():
    return _PAYLOAD, _SYMBOLS

def adapt_pe(raw):
    digest = hashlib.sha256(raw).hexdigest()
    if digest == ORIGINAL_SHA:
        raw = fix_core(raw)
    elif digest != CORE_FIXED_SHA:
        raise ValueError('Unknown Sony USBFN poll input; apply before tracing')
    blob, symbols = payload()
    if BASE+len(blob)>LIMIT or raw[BASE:BASE+len(blob)] != bytes(len(blob)):
        raise ValueError('Poll error code overlaps occupied executable bytes')
    result = bytearray(raw)
    for site, (name, expected) in SITES.items():
        if raw[site:site+4] != bytes.fromhex(expected):
            raise ValueError('Unknown poll instruction at '+hex(site))
        result[site:site+4] = branch(site, symbols[name])
    for site, (expected, instruction) in MOVES.items():
        if raw[site:site+4] != bytes.fromhex(expected):
            raise ValueError('Unknown EventHandler instruction at '+hex(site))
        struct.pack_into('<I', result, site, instruction)
    result[BASE:BASE+len(blob)] = blob
    return bytes(result)

def change_ranges():
    """Half-open RVA/file ranges added on top of core_errors (PE is flat)."""
    blob, _ = payload()
    return [(site, site+4) for site in sorted(set(SITES) | set(MOVES))] + [(BASE, BASE+len(blob))]
