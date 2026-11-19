"""Pure metadata for D27 readonly root windows inside Sony unixnu, never userdata."""
import hashlib
import struct

OS_SHA = '5371e392912dbc5f6f9677d4987c726e15fd7afc519b3644d8d6694777182ad5'
SYSTEMOS_SHA = '34b6010eb6329ca1c942c374df1b157c40cfc36b1120b0c2ec811ea69ed3b686'
PART_BYTES = 64 << 30
FIRST_LBA = 45679360


def manifest():
    """Official SHNGROOT v1 format; all windows readonly, no Data/log writes."""
    data = bytearray(4096)
    data[:8] = b'SHNGROOT'
    struct.pack_into('<II', data, 8, 1, 2)
    cursor = 1 << 20
    windows = []
    for i, (name, size, digest) in enumerate([
        ('OS', 9537847296, OS_SHA), ('SystemOS', 6012534784, SYSTEMOS_SHA),
    ]):
        if cursor % (1 << 20) or size % 4096 or cursor + size > PART_BYTES:
            raise ValueError('Unaligned or out-of-partition window')
        struct.pack_into('<32sQQII32s', data, 24 + 128 * i,
                         name.encode(), cursor, size, 512, 1, bytes.fromhex(digest))
        windows.append(dict(name=name, offset=cursor, bytes=size, sha256=digest,
                            absolute_start=FIRST_LBA * 4096 + cursor, readonly=True))
        cursor = (cursor + size + (1 << 20) - 1) & -(1 << 20)
    struct.pack_into('<Q', data, 16, cursor)
    data[4064:] = hashlib.sha256(data[:4064]).digest()
    return bytes(data), dict(partition='/dev/block/sda98', partition_label='unixnu',
                            first_lba=FIRST_LBA, last_lba=62456575, sector_bytes=4096,
                            partition_bytes=PART_BYTES, image_bytes=cursor, windows=windows,
                            persistent_data_enabled=False, persistent_logs_enabled=False,
                            unused_tail_bytes=PART_BYTES-cursor,
                            iphone='iPhone14,7', target='D27', build='24A446', version='27.0.1',
                            boot_entry_enabled=False, springboard_verified=False)
