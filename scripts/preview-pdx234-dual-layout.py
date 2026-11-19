#!/usr/bin/env python3
"""Make a host-only PDX234 64 GiB geometry preview from read-only captures.

The result is not a recovery apply bundle. No ADB, ioctl or device writes exist
in this tool; recovery/kernel/bootloader compatibility must be qualified later.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import uuid
import zlib

TABLE_SHA256 = 'b688ba781f9e6b0d819b75d8a930cddfc864534891370bdc3c8739171641da6e'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def preview(primary, backup, sector, capacity, gpt_module):
    old = gpt_module.GPT(primary, backup, sector, capacity // sector)
    if sector != 4096 or capacity != 255844155392 or old.h['count'] != 97 or sha(old.table) != TABLE_SHA256:
        raise ValueError('Require the exact read-only captured PDX234 GPT')
    if len(old.entries) != 97:
        raise ValueError('Expected all declared entries to be occupied')
    user = next(e for e in old.entries if e['name'] == 'userdata')
    rddata = next(e for e in old.entries if e['name'] == 'rddata')
    if (user['index'], rddata['index'], user['end'] + 1, rddata['end']) != (96, 97, rddata['start'], old.h['last']):
        raise ValueError('Unexpected userdata/rddata geometry')
    # 128 entries fit the EXISTING four 4096-byte GPT table sectors. No table
    # relocation, usable-LBA change, entry renumbering or partition movement.
    count = 128
    old_length, length = len(old.table), count * 128
    if (length != old.h['blocks'] * sector or
            any(primary[2 * sector + old_length:2 * sector + length]) or
            any(backup[old_length:length])):
        raise ValueError('Additional GPT entries are not backed by existing zero padding')
    table = bytearray(old.table + bytes(length - old_length))
    requested = 64 << 30
    alignment = (1 << 20) // sector
    end = (user['end'] + 1) // alignment * alignment - 1
    start = end + 1 - requested // sector
    if start <= user['start'] or end >= rddata['start']:
        raise ValueError('Requested window does not fit inside original userdata')
    struct.pack_into('<Q', table, 95 * 128 + 40, start - 1)
    entry = bytearray(128)
    entry[:16] = gpt_module.LINUX_DATA
    # Deterministic preview identity; deployment must make and record a new plan.
    entry[16:32] = uuid.uuid5(uuid.UUID(bytes_le=old.h['guid']), 'pdx234-64gib-preview-only').bytes_le
    struct.pack_into('<QQQ', entry, 32, start, end, 0)
    entry[56:68] = 'unixnu'.encode('utf-16-le')
    table[97 * 128:98 * 128] = entry
    new_primary, new_backup = bytearray(primary), bytearray(backup)
    new_primary[2 * sector:2 * sector + length] = table
    new_backup[:length] = table
    for region, offset in ((new_primary, sector), (new_backup, len(backup) - sector)):
        struct.pack_into('<I', region, offset + 80, count)
        struct.pack_into('<I', region, offset + 88, zlib.crc32(table))
        struct.pack_into('<I', region, offset + 16, 0)
        struct.pack_into('<I', region, offset + 16, zlib.crc32(region[offset:offset + 92]))
    candidate = gpt_module.GPT(bytes(new_primary), bytes(new_backup), sector, capacity // sector)
    # All original partitions except userdata are byte-for-byte identical.
    for i in range(97):
        before, after = old.table[i * 128:(i + 1) * 128], candidate.table[i * 128:(i + 1) * 128]
        if i == 95:
            if before[:40] != after[:40] or before[48:] != after[48:]:
                raise ValueError('Userdata identity/start/type/attributes changed')
        elif before != after:
            raise ValueError('An unrelated GPT partition changed')
    if (old.h['guid'] != candidate.h['guid'] or old.h['first'] != candidate.h['first'] or
            old.h['last'] != candidate.h['last'] or old.h['table'] != candidate.h['table'] or
            primary[:sector] != new_primary[:sector]):
        raise ValueError('GPT placement, usable range, disk identity or MBR changed')
    layout = dict(sector_bytes=sector, old_userdata_bytes=(user['end'] - user['start'] + 1) * sector,
                  new_userdata_bytes=(start - user['start']) * sector,
                  userdata_start_lba=user['start'], userdata_old_end_lba=user['end'],
                  userdata_preview_end_lba=start - 1,
                  unixnu_preview_slot=98, unixnu_start_lba=start, unixnu_end_lba=end,
                  unixnu_bytes=requested, alignment_gap_before_rddata_bytes=(user['end'] - end) * sector,
                  rddata_start_lba=rddata['start'], rddata_end_lba=rddata['end'],
                  rddata_entry_unchanged=True, all_other_original_entries_unchanged=True,
                  old_entry_count=97, preview_entry_count=count,
                  table_sectors_unchanged=old.h['blocks'], table_padding_verified_zero=True,
                  original_table_sha256=sha(old.table), new_table_sha256=sha(candidate.table),
                  both_gpt_crcs_and_no_overlap_verified=True)
    return bytes(new_primary), bytes(new_backup), layout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--official-dual-sys', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.official_dual_sys.resolve()))
    import gpt
    import partition
    capture = json.loads((args.capture / 'capture.json').read_text())
    for name, record in capture['captures'].items():
        content = (args.capture / name).read_bytes()
        if len(content) != record['bytes'] or sha(content) != record['sha256']:
            raise ValueError('Read-only capture changed: ' + name)
    primary = (args.capture / 'gpt-primary-region.bin').read_bytes()
    backup = (args.capture / 'gpt-backup-region.bin').read_bytes()
    if (primary != (args.capture / 'gpt-primary-region-after.bin').read_bytes() or
            backup != (args.capture / 'gpt-backup-region-after.bin').read_bytes()):
        raise ValueError('GPT changed during capture')
    new_primary, new_backup, layout = preview(primary, backup, capture['sector_bytes'], capture['disk_bytes'], gpt)
    raw = (args.capture / 'f2fs-superblocks.bin').read_bytes()
    superblock = raw[1024:4096]
    if len(raw) != 8192 or superblock != raw[5120:8192] or struct.unpack_from('<I', superblock)[0] != 0xf2f52010:
        raise ValueError('F2FS superblocks invalid or unequal')
    fields = {name: struct.unpack_from('<I', superblock, offset)[0] for name, offset in
              (('log_sector_size', 8), ('log_sectors_per_block', 12), ('log_block_size', 16),
               ('log_blocks_per_segment', 20), ('segments_per_section', 24), ('feature', 2180))}
    blocks = struct.unpack_from('<Q', superblock, 36)[0]
    simple = (fields['log_sector_size'] + fields['log_sectors_per_block'] == 12 and
              fields['log_block_size'] == 12 and fields['log_blocks_per_segment'] == 9 and
              fields['segments_per_section'] == 1 and not superblock[2201] and not fields['feature'] & 2)
    limit = layout['new_userdata_bytes'] // 4096
    after = partition.expected_blocks(blocks, limit)
    request = after - blocks % 512
    statfs = (args.capture / 'statfs.txt').read_text()
    available = int(re.search(r'Available:\s*(\d+)', statfs)[1])
    topology = (args.capture / 'mapper-topology.txt').read_text().splitlines()
    holders = set(topology[2].split())
    mapped = Path(capture['mapped']).name
    additional_holders = sorted(holders - {mapped})
    report = dict(target='Sony PDX234', preview_only=True, deployable=False,
                  layout=layout,
                  f2fs=dict(fields, superblock_copies_equal=True, simple_geometry_supported=simple,
                            blocks_before=blocks, limit_blocks=limit, ioctl_request_blocks=request,
                            expected_blocks_after=after, expected_bytes_after=after * 4096,
                            partition_slack_after_bytes=layout['new_userdata_bytes'] - after * 4096,
                            available_blocks_at_capture=available,
                            official_space_precheck_passes=blocks - request < available,
                            shrink_executed=False),
                  mapping=dict(raw_and_decrypted_sizes_equal=capture['device_bytes']['userdata'] ==
                               capture['device_bytes']['mapped'], single_backing_device=topology[1].strip() == 'sda96',
                               additional_raw_holders=additional_holders,
                               original_helper_topology_would_accept=not additional_holders),
                  official_requirements_unmet=['userdata is not last occupied partition',
                    'all 97 currently declared GPT entries are occupied',
                    'current session is Android, not a qualified decrypting TWRP',
                    'additional active userdata holders must be absent in recovery'],
                  independent_qualifications_needed=['bootloader/recovery acceptance of entry count 128 and slot 98',
                    'recovery wrappedkey metadata decryption and full-size mapping',
                    'recovery F2FS resize ioctl implementation and successful data migration',
                    'post-reboot Android decryption, files and boot',
                    'XNU root and Data/log writes restricted to unixnu, never Android userdata'],
                  official_sources=['https://unixnu.com/zh/porting/dual-system-partition',
                                    'https://unixnu.com/zh/concepts/userdata',
                                    'https://unixnu.com/zh/porting/ufs'],
                  offline_validation=dict(both_gpt_copies_reparsed=True, unrelated_partitions_preserved=True),
                  device_writes=False, resize_ioctl_issued=False)
    args.out.mkdir(parents=True, exist_ok=False)
    for name, data in (('gpt-primary.preview.bin', new_primary), ('gpt-backup.preview.bin', new_backup)):
        (args.out / name).write_bytes(data)
    report['preview_sha256'] = dict(primary=sha(new_primary), backup=sha(new_backup))
    (args.out / 'preview.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
