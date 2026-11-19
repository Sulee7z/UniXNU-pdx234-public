#!/usr/bin/env python3
"""Read APFS container/volume identity through its physical object map, without mounting."""
import argparse
import json
from pathlib import Path
import struct
import uuid


def fletcher64(data: bytes) -> int:
    a = b = 0
    modulo = 0xffffffff
    for (word,) in struct.iter_unpack('<I', data[8:]):
        a = (a + word) % modulo
        b = (b + a) % modulo
    low = modulo - ((a + b) % modulo)
    high = modulo - ((a + low) % modulo)
    return low | (high << 32)


class Container:
    def __init__(self, path: Path):
        self.path = path
        self.file = path.open('rb')
        self.bytes = path.stat().st_size
        header = self.file.read(4096)
        if header[32:36] != b'NXSB':
            raise RuntimeError('Expected a raw APFS container')
        self.block_size = struct.unpack_from('<I', header, 36)[0]
        if self.block_size not in (4096, 8192, 16384):
            raise RuntimeError('Unsupported APFS block size')
        self.blocks = struct.unpack_from('<Q', header, 40)[0]
        if self.blocks * self.block_size > self.bytes:
            raise RuntimeError('Container exceeds raw image bounds')
        self.nx = self.read_block(0)
        self.xid = struct.unpack_from('<Q', self.nx, 16)[0]
        omap_address = struct.unpack_from('<Q', self.nx, 0xA0)[0]
        omap = self.read_block(omap_address)
        if struct.unpack_from('<I', omap, 24)[0] & 0xffff != 11:
            raise RuntimeError('Container object map has wrong type')
        self.omap_root = struct.unpack_from('<Q', omap, 0x30)[0]

    def read_block(self, number: int) -> bytes:
        if not 0 <= number < self.blocks:
            raise RuntimeError('Metadata block is outside the container')
        self.file.seek(number * self.block_size)
        data = self.file.read(self.block_size)
        if len(data) != self.block_size:
            raise RuntimeError('Short metadata block')
        if struct.unpack_from('<Q', data)[0] != fletcher64(data):
            raise RuntimeError(f'APFS metadata checksum failed at block {number}')
        return data

    def lookup(self, oid: int) -> int:
        address, visited = self.omap_root, set()
        for _ in range(16):
            if address in visited:
                raise RuntimeError('Object-map node loop')
            visited.add(address)
            node = self.read_block(address)
            flags, level, count = struct.unpack_from('<HHI', node, 32)
            if not flags & 4 or count > self.block_size // 4:
                raise RuntimeError('Expected a bounded fixed-key object-map node')
            table_offset, table_bytes = struct.unpack_from('<HH', node, 40)
            table_start = 56 + table_offset
            key_base = table_start + table_bytes
            value_base = self.block_size - (40 if flags & 1 else 0)
            if count * 4 > table_bytes or key_base > value_base:
                raise RuntimeError('Invalid object-map key table')
            chosen = None
            prior = None
            for index in range(count):
                ko, vo = struct.unpack_from('<HH', node, table_start + 4 * index)
                key_offset, value_offset = key_base + ko, value_base - vo
                if key_offset < key_base or key_offset + 16 > value_base:
                    raise RuntimeError('Object-map key outside node')
                key = struct.unpack_from('<QQ', node, key_offset)
                if prior is not None and key < prior:
                    raise RuntimeError('Object-map keys are not sorted')
                prior = key
                if key <= (oid, self.xid):
                    chosen = (key, value_offset)
            if chosen is None:
                raise RuntimeError('No object-map record precedes this object')
            key, offset = chosen
            if level == 0:
                if key[0] != oid or offset < key_base or offset + 16 > value_base:
                    raise RuntimeError('No matching volume object-map record')
                value_flags, size, physical = struct.unpack_from('<IIQ', node, offset)
                if value_flags & (1 | 4 | 8) or size != self.block_size:
                    raise RuntimeError('Deleted, encrypted or unsupported volume object')
                return physical
            if offset < key_base or offset + 8 > value_base:
                raise RuntimeError('Child pointer outside object-map node')
            address = struct.unpack_from('<Q', node, offset)[0]
        raise RuntimeError('Excessive object-map depth')

    def inspect(self) -> dict:
        volume_ids = [value for (value,) in struct.iter_unpack('<Q', self.nx[0xB8:0x3D8]) if value]
        volumes = []
        for oid in volume_ids:
            address = self.lookup(oid)
            block = self.read_block(address)
            if block[32:36] != b'APSB' or struct.unpack_from('<Q', block, 8)[0] != oid:
                raise RuntimeError('Object map did not resolve the volume superblock')
            volumes.append(dict(object_id=oid, physical_block=address,
                volume_uuid=str(uuid.UUID(bytes=block[0xF0:0x100])).upper(),
                name=block[0x2C0:0x3C0].split(b'\0', 1)[0].decode('utf-8'),
                role=struct.unpack_from('<H', block, 0x3C4)[0],
                volume_group_uuid=str(uuid.UUID(bytes=block[0x3F0:0x400])).upper(),
                files=struct.unpack_from('<Q', block, 0xB8)[0],
                directories=struct.unpack_from('<Q', block, 0xC0)[0]))
        return dict(path=str(self.path), bytes=self.blocks * self.block_size,
                    block_size=self.block_size, container_xid=self.xid,
                    container_uuid=str(uuid.UUID(bytes=self.nx[0x48:0x58])).upper(),
                    volumes=volumes, metadata_checksums_verified=True, read_only=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    image = Container(args.image)
    try:
        report = image.inspect()
    finally:
        image.file.close()
    with args.report.open('x', encoding='utf-8') as output:
        output.write(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
