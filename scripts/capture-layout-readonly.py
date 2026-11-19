#!/usr/bin/env python3
"""Read and CRC-check Xperia GPT; never modify device storage or filesystems."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import uuid
import zlib

PROJECT = Path(__file__).resolve().parents[3]
OUT = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z'
ADB = [str(PROJECT / 'tools/platform-tools/adb.exe'), '-P', '5037', '-s', 'PDX_DEVICE_SERIAL']


def shell(command):
    return subprocess.check_output([*ADB, 'shell', command], timeout=30).decode().strip()


def read_blocks(first, count, sector):
    if first < 0 or not 0 < count * sector <= 1 << 20:
        raise ValueError('Refuse excessive GPT read')
    raw = subprocess.check_output([*ADB, 'exec-out',
        f'dd if=/dev/block/sda bs={sector} skip={first} count={count} 2>/dev/null'], timeout=30)
    if len(raw) != count * sector:
        raise ValueError('Binary GPT read length differs')
    return raw


def decode(raw, lba):
    if raw[:8] != b'EFI PART':
        raise ValueError('GPT header missing')
    version, size, expected = struct.unpack_from('<III', raw, 8)
    if version != 0x10000 or not 92 <= size <= len(raw):
        raise ValueError('GPT version/size mismatch')
    header = bytearray(raw[:size])
    struct.pack_into('<I', header, 16, 0)
    if zlib.crc32(header) != expected:
        raise ValueError('GPT header CRC differs')
    current, alternate, first, last = struct.unpack_from('<4Q', raw, 24)
    entries, count, entry_size, entry_crc = struct.unpack_from('<QIII', raw, 72)
    if current != lba or entry_size != 128 or not 0 < count <= 4096:
        raise ValueError('Unexpected GPT geometry')
    return dict(current_lba=current, backup_lba=alternate, first_usable=first, last_usable=last,
                disk_guid=str(uuid.UUID(bytes_le=raw[56:72])), entry_lba=entries,
                entry_count=count, entry_bytes=entry_size, entries_crc=entry_crc)


def main():
    output = OUT / 'gpt-layout-readonly.json'
    if output.exists():
        raise RuntimeError('Preserve previous GPT observation')
    sector = int(shell('blockdev --getss /dev/block/sda'))
    capacity = int(shell('blockdev --getsize64 /dev/block/sda'))
    if sector not in (512, 4096) or capacity % sector:
        raise ValueError('Unsupported sector geometry')
    primary_raw = read_blocks(1, 1, sector)
    primary = decode(primary_raw, 1)
    backup_raw = read_blocks(capacity // sector - 1, 1, sector)
    backup = decode(backup_raw, capacity // sector - 1)
    tables = []
    for label, header in (('primary', primary), ('backup', backup)):
        size = header['entry_count'] * header['entry_bytes']
        table = read_blocks(header['entry_lba'], (size + sector - 1)//sector, sector)[:size]
        if zlib.crc32(table) != header['entries_crc']:
            raise ValueError('GPT table CRC differs')
        (OUT / f'gpt-{label}-header.bin').write_bytes(primary_raw if label == 'primary' else backup_raw)
        (OUT / f'gpt-{label}-entries.bin').write_bytes(table)
        tables.append(table)
    if (tables[0] != tables[1] or primary['disk_guid'] != backup['disk_guid'] or
            primary['backup_lba'] != backup['current_lba'] or backup['backup_lba'] != 1):
        raise ValueError('GPT copies disagree')
    parts = []
    for index in range(primary['entry_count']):
        entry = tables[0][index*128:(index+1)*128]
        if entry[:16] == bytes(16):
            continue
        first, last, attrs = struct.unpack_from('<3Q', entry, 32)
        name = entry[56:128].decode('utf-16-le').split('\0')[0]
        if not primary['first_usable'] <= first <= last <= primary['last_usable']:
            raise ValueError('Partition outside usable disk')
        parts.append(dict(slot=index+1, name=name, first_lba=first, last_lba=last,
                          bytes=(last-first+1)*sector, attributes=attrs))
    ordered = sorted(parts, key=lambda item: item['first_lba'])
    if any(a['last_lba'] >= b['first_lba'] for a,b in zip(ordered, ordered[1:])):
        raise ValueError('GPT contains overlapping partitions')
    userdata = [item for item in parts if item['name'] == 'userdata']
    if len(userdata) != 1:
        raise ValueError('Userdata must be unique')
    following = [p for p in ordered if p['first_lba'] > userdata[0]['last_lba']]
    result = dict(serial='PDX_DEVICE_SERIAL', sector_bytes=sector, disk_bytes=capacity,
                  primary=primary, backup=backup, copies_and_crcs_match=True,
                  partitions=parts, partitions_after_userdata=following,
                  official_last_userdata_precondition_met=not following,
                  existing_unixnu=any(p['name'] == 'unixnu' for p in parts),
                  table_sha256=hashlib.sha256(tables[0]).hexdigest(), device_writes=False)
    output.write_text(json.dumps(result, indent=2))
    print(json.dumps({k:v for k,v in result.items() if k not in ('primary','backup','partitions')}, indent=2))


if __name__ == '__main__':
    main()
