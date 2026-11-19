#!/usr/bin/env python3
"""Inspect the actual Sony FD for architectural-service providers and menu modules.

This is a container/DEPEX check, not proof that driver entry points ran on hardware.
The parser deliberately accepts only the FV/FFS/LZMA formats used by this port.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import struct
import uuid

LZMA_GUID = 'ee4e5898-3914-4259-9d6e-dc7bd79403cf'
CAPSULE_GUID = '42857f0a-13f2-4b21-8a23-53d3f714b840'
VARIABLE_WRITE = uuid.UUID('6441f818-6362-4e44-b570-7dba31dd2453').bytes_le
# Providers of the 13 mandatory entries in Mu DxeProtocolNotify.c:mArchProtocols.
ARCH = {
    'f80697e9-7fd6-4665-8646-88e33ef71dfc': ('SecurityStubDxe', ['Security']),
    'b8d9777e-d72a-451f-9bdb-bafb52a68415': ('ArmCpuDxe', ['CPU']),
    '4c6e0267-c77d-410d-8100-1495911a989d': ('MetronomeDxe', ['Metronome']),
    '49ea041e-6752-42ca-b0b1-7344fe2546b7': ('ArmTimerDxe', ['Timer']),
    '6d33944a-ec75-4855-a54d-809c75241f6c': ('BdsDxe', ['Bds']),
    'f099d67f-71ae-4c36-b2a3-dceb0eb2b7d8': ('WatchdogTimer', ['Watchdog Timer']),
    'b601f8c4-43b7-4784-95b1-f4226cb40cee': ('RuntimeDxe', ['Runtime']),
    'cbd2e4d5-7068-4ff5-b462-9822b4ad8d60': ('VariableRuntimeDxe', ['Variable', 'Variable Write']),
    CAPSULE_GUID: ('CapsuleRuntimeDxe', ['Capsule']),
    'fcabe6a7-7953-4a84-b7ec-d29e89b62e87': ('EmbeddedMonotonicCounter', ['Monotonic Counter']),
    '4b28e4c7-ff36-4e10-93cf-a82159e777c5': ('ResetSystemRuntimeDxe', ['Reset']),
    'b336f62d-4135-4a55-ae4e-4971bbf0885d': ('RealTimeClock', ['Real Time Clock']),
}
MENU = {
    '9b665204-a133-47a2-9396-9e2b370a4e25': 'UniXNU',
    '29b950cf-586d-49ea-9d71-f88645ccdaf6': 'UniXNUDxe',
    '1b64af87-8415-4b57-9b16-680d70913b9f': 'DarwinBoot',
    '75ca63ad-fbae-4a06-92a0-f937c671251d': 'UniXNURamDiskDxe',
    '6b38f7b4-ad98-40e9-9093-aca2b5a253c4': 'DiskIoDxe',
    '961578fe-b6b7-44c3-af35-6bc705cd2b1f': 'Fat',
    'cd3bafb6-50fb-4fe8-8e4e-ab74d2c1a600': 'EnglishDxe',
    'cccb0c28-4b24-11d5-9a5a-0090273fc14d': 'GraphicsConsoleDxe',
    '51ccf399-4fdf-4e55-a45b-e123f84d456a': 'ConPlatformDxe',
    '408edcec-cf6d-477c-a5a8-b4844e3de281': 'ConSplitterDxe',
    'ebf342fe-b1d3-4ef8-957c-8048606ff671': 'SetupBrowser',
    '52fb2778-a24c-4431-a312-f83c18fb0d6d': 'PdxConfigFsDxe',
    'b83d8be0-ff86-4d40-95d5-eba0f20b0612': 'PdxKeyInputDxe',
    '61f1e287-32b4-4dcf-9212-53a3ed86f73d': 'PdxAndroidResume',
}


def sections(data: bytes) -> list[tuple[int, bytes]]:
    result = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            if any(data[offset:]):
                raise ValueError('Nonzero section alignment padding')
            break
        size = int.from_bytes(data[offset:offset + 3], 'little')
        header = 4
        if size == 0xffffff:
            if len(data) - offset < 8:
                raise ValueError('Truncated extended section')
            size = struct.unpack_from('<I', data, offset + 4)[0]
            header = 8
        if size < header or offset + size > len(data):
            raise ValueError('Invalid section size')
        result.append((data[offset + 3], data[offset + header:offset + size]))
        offset = (offset + size + 3) & ~3
    return result


def volume_files(data: bytes, depth: int = 0) -> dict[str, list[tuple[int, bytes]]]:
    if depth > 4 or len(data) < 72 or data[40:44] != b'_FVH':
        raise ValueError('Invalid FV header or excessive nesting')
    size = struct.unpack_from('<Q', data, 32)[0]
    header = struct.unpack_from('<H', data, 48)[0]
    if not 56 <= header <= size <= len(data) or header % 2:
        raise ValueError('Invalid FV bounds')
    if sum(struct.unpack('<' + 'H' * (header // 2), data[:header])) & 0xffff:
        raise ValueError('FV header checksum failed')
    offset = (header + 7) & ~7
    result = {}
    while offset + 24 <= size:
        if data[offset:offset + 24] == b'\xff' * 24:
            break
        length = int.from_bytes(data[offset + 20:offset + 23], 'little')
        if length < 24 or length == 0xffffff or offset + length > size:
            raise ValueError('Invalid or unsupported FFS size')
        file_type = data[offset + 18]
        if file_type != 0xf0:  # FFS pad file has no section stream.
            guid = str(uuid.UUID(bytes_le=data[offset:offset + 16]))
            stream = sections(data[offset + 24:offset + length])
            if guid in result:
                raise ValueError('Duplicate FFS GUID')
            result[guid] = stream
            if file_type == 0x0b:  # FV_IMAGE
                for section_type, body in stream:
                    if section_type != 2 or len(body) < 20:
                        raise ValueError('Expected LZMA guided FV image')
                    tool_guid = str(uuid.UUID(bytes_le=body[:16]))
                    data_offset, attributes = struct.unpack_from('<HH', body, 16)
                    if tool_guid != LZMA_GUID or data_offset != 24 or attributes != 1:
                        raise ValueError('Unsupported guided FV encoding')
                    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=128 << 20)
                    inner = decoder.decompress(body[20:], max_length=64 << 20)
                    if not decoder.eof or decoder.unused_data:
                        raise ValueError('Incomplete or oversized LZMA FV')
                    # GenFv inserts an empty RAW section for FV alignment.
                    nested = [(kind, payload) for kind, payload in sections(inner)
                              if (kind, payload) != (0x19, b'')]
                    if len(nested) != 1 or nested[0][0] != 0x17:
                        raise ValueError('Expected a single nested FV section')
                    children = volume_files(nested[0][1], depth + 1)
                    if result.keys() & children.keys():
                        raise ValueError('Duplicate nested FFS GUID')
                    result.update(children)
        offset = (offset + length + 7) & ~7
    return result


def inspect_firmware(data: bytes) -> dict:
    if len(data) != 0x300000:
        raise ValueError('Sony FD must be exactly 3 MiB')
    files = volume_files(data)
    missing_arch = [p for guid, (_, protocols) in ARCH.items() if guid not in files for p in protocols]
    missing_menu = [name for guid, name in MENU.items() if guid not in files]
    for guid in (ARCH.keys() | MENU.keys()) & files.keys():
        if not any(kind in (0x10, 0x12) for kind, _ in files[guid]):
            raise ValueError(f'Required FFS has no PE/TE image: {guid}')
    capsule_depex = [body for kind, body in files.get(CAPSULE_GUID, []) if kind == 0x13]
    capsule_depex_ok = len(capsule_depex) == 1 and b'\x02' + VARIABLE_WRITE in capsule_depex[0]
    if CAPSULE_GUID in files and not capsule_depex_ok:
        raise ValueError('Capsule driver lacks its VariableWrite architectural dependency')
    return dict(fd_sha256=hashlib.sha256(data).hexdigest(), ffs_files=len(files),
                required_arch_protocols=13, missing_arch_providers=missing_arch,
                missing_menu_modules=missing_menu, capsule_variable_write_depex=capsule_depex_ok,
                passed=not missing_arch and not missing_menu, hardware_execution_verified=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fd', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    report = inspect_firmware(args.fd.read_bytes())
    text = json.dumps(report, indent=2) + '\n'
    if args.report:
        with args.report.open('x', encoding='utf-8') as output:
            output.write(text)
    print(text, end='')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
