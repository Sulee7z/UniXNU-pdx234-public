"""Minimal067 menu correction; no kernel, firmware or feature-selection changes."""
import hashlib
import struct
from darwin_boot_args import validate

PRIOR_IMAGE_SHA='929e240b9a9910e2496eaa736794a2b74030b06d4a9b4202d2cb8825bd59e901'
KERNEL_SHA='f204912a04e8a922e0b9f2897991252befe3fca35f4fc5919b6242859950ef0a'
FIRMWARE_SHA='30777cf8cafcb51e09d48a7ec5437575fcae816fe41575dfed6ede1734abe3ea'
LOADER_SHA='f533ab96d20e4f4c723a9ab7ff1dada059ab938b91b9b42aded21d5d4488b82a'
REMOVED_DEFAULTS=['gpu-fence-wake=1','gpu-pause-us=1000']


def shorten(arguments):
    if len(arguments.encode('ascii'))!=1041:raise ValueError('Exact1041-byte067 request required')
    tokens=arguments.split()
    if (arguments!=' '.join(tokens) or tokens.count('build-tag=PDX067')!=1 or
            len(tokens)!=len({token.split('=')[0] for token in tokens})):
        raise ValueError('Unexpected067 argument selection')
    for token in REMOVED_DEFAULTS:
        if tokens.count(token)!=1:raise ValueError('Expected explicit compiled default: '+token)
    fixed=' '.join('build-tag=PDX068' if token=='build-tag=PDX067' else token
                   for token in tokens if token not in REMOVED_DEFAULTS)
    result=validate(fixed)
    if result['ascii_bytes']!=1006:raise ValueError('Unexpected corrected request length')
    return fixed


def loader_guard(pe):
    """Bind source regression to the actual unchanged loader carried in the FD."""
    if hashlib.sha256(pe).hexdigest()!=LOADER_SHA:raise ValueError('Wrong retained DarwinBoot executable')
    header=struct.unpack_from('<I',pe,60)[0];count=struct.unpack_from('<H',pe,header+6)[0]
    optional=struct.unpack_from('<H',pe,header+20)[0]
    def read(va,size):
        for index in range(count):
            at=header+24+optional+index*40
            name,virtual_size,rva,raw_size,raw_at=struct.unpack_from('<8s4I',pe,at)
            if rva<=va and va+size<=rva+raw_size:return pe[raw_at+va-rva:raw_at+va-rva+size]
        raise ValueError('Loader instruction range is not file-backed')
    expected=bytes.fromhex('880a40f9680300b4e1031faa09796178090300343ff80ff1a81e00543f010271621e0054c96a213821040091f8ffff17')
    if read(0x13dc,len(expected))!=expected:raise ValueError('Actual loader ASCII/1023 guard differs')
    # CMP index,#1022 / B.HI rejection after seeing a non-NUL char is equivalent
    # to C's index>=1023; the valid maximum is1023 characters plus a finalNUL.
    return dict(passed=True,loader_sha256=LOADER_SHA,guard_rva='0x13dc',guard_bytes=len(expected),
        guard_sha256=hashlib.sha256(expected).hexdigest(),capacity=1024,max_ascii_bytes=1023,
        source_loop_matches_retained_binary=True,firmware_modified=False)
