#!/usr/bin/env python3
"""Reconstruct the photographed GPT header from the immutable old Sony capture."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--screen-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    sha = lambda data: hashlib.sha256(data).hexdigest()
    header = (args.baseline / 'gpt-header.bin').read_bytes()
    table = (args.baseline / 'gpt-table.bin').read_bytes()
    current_header = (args.current / 'gpt-header.bin').read_bytes()
    current_table = (args.current / 'gpt-table.bin').read_bytes()
    if len(header) != 4096 or len(table) != 16384 or len(current_header) != 4096 or len(current_table) != 16384:
        raise ValueError('Unexpected capture size')
    matches = []
    for slot in (67, 82):
        old_attributes = struct.unpack_from('<Q', table, slot*128+48)[0]
        for status in range(16):
            changed = bytearray(table)
            attributes = (old_attributes & ~(0x78 << 48)) | (status << 51)
            struct.pack_into('<Q', changed, slot*128+48, attributes)
            h = bytearray(header)
            crc = zlib.crc32(changed[:97*128])
            struct.pack_into('<I', h, 88, crc)
            h[16:20] = bytes(4)
            struct.pack_into('<I', h, 16, zlib.crc32(h[:92]))
            if sha(h) == args.screen_sha256:
                matches.append(dict(entry=slot+1, attributes=hex(attributes), table_crc=hex(crc),
                                    reconstructed_header_sha256=sha(h)))
    if len(matches) != 1:
        raise ValueError('Photographed header not uniquely reconstructed from boot retry/success state')
    # Android's later snapshot is independent of the photographed XNU snapshot.
    stable_headers = []
    stable_tables = []
    for h, t in ((header, table), (current_header, current_table)):
        normalized_h = bytearray(h)
        normalized_h[16:20] = bytes(4)
        normalized_h[88:92] = bytes(4)
        stable_headers.append(sha(normalized_h))
        normalized_t = bytearray(t)
        for slot in (67, 82):
            attributes = struct.unpack_from('<Q', t, slot*128+48)[0]
            struct.pack_into('<Q', normalized_t, slot*128+48, attributes & ~(0x78 << 48))
        stable_tables.append(sha(normalized_t[:97*128]))
    if len(set(stable_headers)) != 1 or len(set(stable_tables)) != 1:
        raise ValueError('Stable disk identity changed')
    result = dict(matches=matches, normalized_header_sha256=stable_headers[0],
                  normalized_table_sha256=stable_tables[0], passed=True, device_operations=False,
                  scope='Host reconstruction and independent later ADB snapshot; not an XNU table dump')
    args.out.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
