"""PDX234 geometry adapter; pure bytes in/out, deliberately no device writer."""
import struct
import uuid
import zlib

SECTOR = 4096
TOTAL = 62461952
USER_START, USER_END = 5933398, 62456826
RDATA_START, RDATA_END = 62456827, 62461946
DISK_GUID = '98101b32-bbe2-4bf2-a06e-2bb33d000c20'
USER_GUID = '6ea4c6d3-957a-ab5b-7455-749893e94191'
RDATA_GUID = 'f5ad7070-c0cd-4161-8e53-a89914a92353'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def plan(primary, backup, sector, total, requested, gpt, *, new_guid=None):
    require((sector, total) == (SECTOR, TOTAL), 'Unexpected Sony disk geometry')
    require(requested == 64 << 30, 'This reviewed adapter supports exactly 64 GiB')
    original = gpt.GPT(primary, backup, sector, total)
    require(str(uuid.UUID(bytes_le=original.h['guid'])) == DISK_GUID, 'Disk identity mismatch')
    require(original.h['count'] == 97 and original.h['blocks'] == 4,
            'Expected 97-entry Sony GPT in four reserved table sectors')
    require(len(original.entries) == 97, 'Unexpected occupied entry count')
    require(not any(e['name'].lower() == 'unixnu' for e in original.entries),
            'Existing unixnu partition; do not split twice')
    users = [e for e in original.entries if e['name'] == 'userdata']
    tails = [e for e in original.entries if e['name'] == 'rddata']
    require(len(users) == len(tails) == 1, 'Ambiguous userdata/rddata names')
    user, tail = users[0], tails[0]
    require((user['index'], user['start'], user['end'], user['guid']) ==
            (96, USER_START, USER_END, USER_GUID), 'Userdata identity or bounds changed')
    require((tail['index'], tail['start'], tail['end'], tail['guid']) ==
            (97, RDATA_START, RDATA_END, RDATA_GUID), 'rddata identity or bounds changed')
    require(user['end'] + 1 == tail['start'] and tail['end'] == original.h['last'],
            'Unexpected trailing partition geometry')
    count = 128
    length, old_length = count * 128, len(original.table)
    require(length == original.h['blocks'] * sector, 'Expansion would relocate GPT tables')
    require(not any(primary[2 * sector + old_length:2 * sector + length]) and
            not any(backup[old_length:length]), 'Nonzero undeclared table padding')
    guid = new_guid if new_guid is not None else uuid.uuid4()
    require(isinstance(guid, uuid.UUID) and guid.int != 0 and
            str(guid) not in {e['guid'] for e in original.entries}, 'Invalid new partition GUID')
    alignment = (1 << 20) // sector
    end = (user['end'] + 1) // alignment * alignment - 1
    start = end + 1 - requested // sector
    require(user['start'] < start <= end < tail['start'], 'New partition exceeds old userdata')
    require(start % alignment == 0 and (end + 1) % alignment == 0, 'Unaligned new partition')
    table = bytearray(original.table + bytes(length - old_length))
    struct.pack_into('<Q', table, 95 * 128 + 40, start - 1)
    entry = bytearray(128)
    entry[:16] = gpt.LINUX_DATA
    entry[16:32] = guid.bytes_le
    struct.pack_into('<QQQ', entry, 32, start, end, 0)
    label = 'unixnu'.encode('utf-16-le')
    entry[56:56 + len(label)] = label
    table[97 * 128:98 * 128] = entry
    a, b = bytearray(primary), bytearray(backup)
    a[2 * sector:2 * sector + length] = table
    b[:length] = table
    for region, offset in [(a, sector), (b, len(b) - sector)]:
        struct.pack_into('<I', region, offset + 80, count)
        struct.pack_into('<I', region, offset + 88, zlib.crc32(table))
        struct.pack_into('<I', region, offset + 16, 0)
        struct.pack_into('<I', region, offset + 16, zlib.crc32(region[offset:offset + 92]))
    result = gpt.GPT(bytes(a), bytes(b), sector, total)
    for index in range(97):
        old = original.table[index * 128:(index + 1) * 128]
        new = result.table[index * 128:(index + 1) * 128]
        if index == 95:
            require(old[:40] == new[:40] and old[48:] == new[48:], 'Userdata identity changed')
        else:
            require(old == new, f'Unrelated partition entry {index + 1} changed')
    require(primary[:sector] == a[:sector], 'Protective MBR changed')
    require(all(original.h[k] == result.h[k] for k in ('first', 'last', 'guid', 'table', 'blocks')),
            'GPT table placement, disk GUID or usable range changed')
    require(not any(result.table[98 * 128:]), 'Unexpected additional partitions')
    return bytes(a), bytes(b), {
        'disk_guid': DISK_GUID, 'sector_bytes': sector, 'disk_bytes': total * sector,
        'userdata': {'index': 96, 'first_lba': USER_START, 'last_lba': start - 1,
                     'bytes': (start - USER_START) * sector, 'guid': USER_GUID},
        'unixnu': {'index': 98, 'first_lba': start, 'last_lba': end,
                   'bytes': requested, 'guid': str(guid)},
        'rddata': {'index': 97, 'first_lba': RDATA_START, 'last_lba': RDATA_END,
                   'guid': RDATA_GUID, 'entry_unchanged': True},
        'gap_before_rddata_bytes': (RDATA_START - end - 1) * sector,
        'gpt_entry_count': count, 'table_sectors_unchanged': True,
        'unrelated_original_entries_unchanged': 96, 'backup_and_primary_crc_valid': True,
        'device_write_interface': False, 'deployable': False,
        'remaining_gates': ['qualified offline boot environment and no userdata holders',
                            'Sony bootloader/kernel acceptance of GPT entry 98 and count 128',
                            'bounded filesystem recreation or verified shrink before use',
                            'root/Data/log image writers explicitly select unixnu, never userdata']}
