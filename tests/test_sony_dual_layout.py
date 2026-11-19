"""Offline-only tests; no device tools, mounts or writes to block devices."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parents[1] / 'sources/UniXNU-main-20261109/scripts/dual_sys'))
import gpt

SPEC = importlib.util.spec_from_file_location('sony_layout', ROOT / 'ci/dual_sys/sony_layout.py')
sony = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sony)


def fixture(*, disk_guid=sony.DISK_GUID, user_end=sony.USER_END,
            rd_start=sony.RDATA_START, user_guid=sony.USER_GUID,
            padding=False, existing_unixnu=False, boot_flags=0):
    sector, total = sony.SECTOR, sony.TOTAL
    table = bytearray(16384)
    for index in range(1, 98):
        entry = bytearray(128)
        entry[:16] = gpt.LINUX_DATA
        guid = uuid.uuid5(uuid.NAMESPACE_DNS, 'synthetic-sony-' + str(index))
        start, end, name = 6 + index * 16, 6 + index * 16 + 7, 'synthetic' + str(index)
        if index == 96:
            start, end, name, guid = sony.USER_START, user_end, 'userdata', uuid.UUID(user_guid)
        if index == 97:
            start, end, name, guid = rd_start, sony.RDATA_END, 'rddata', uuid.UUID(sony.RDATA_GUID)
        if existing_unixnu and index == 1:
            name = 'unixnu'
        entry[16:32] = guid.bytes_le
        struct.pack_into('<QQQ', entry, 32, start, end, boot_flags if index == 68 else 0)
        encoded = name.encode('utf-16-le')
        entry[56:56 + len(encoded)] = encoded
        table[(index - 1) * 128:index * 128] = entry
    if padding:
        table[127 * 128 + 127] = 1
    table_crc = zlib.crc32(table[:97 * 128])

    def header(here, other, location):
        value = bytearray(sector)
        struct.pack_into('<8sIIIIQQQQ16sQIII', value, 0, b'EFI PART', 0x10000,
            92, 0, 0, here, other, 6, sony.RDATA_END, uuid.UUID(disk_guid).bytes_le,
            location, 97, 128, table_crc)
        struct.pack_into('<I', value, 16, zlib.crc32(value[:92]))
        return value

    mbr = bytearray(sector)
    mbr[450] = 0xee
    mbr[510:512] = b'\x55\xaa'
    return bytes(mbr + header(1, total - 1, 2) + table), bytes(table + header(total - 1, 1, total - 5))


class SonyLayoutTests(unittest.TestCase):
    def plan(self, pair=None, **kwargs):
        a, b = pair or fixture()
        return sony.plan(a, b, 4096, sony.TOTAL, 64 << 30, gpt, **kwargs)

    def test_exact_64gib_and_no_rddata_move(self):
        a, b, plan = self.plan()
        result = gpt.GPT(a, b, 4096, sony.TOTAL)
        self.assertEqual(plan['unixnu']['bytes'], 64 << 30)
        self.assertEqual(plan['unixnu']['first_lba'], 45679360)
        self.assertEqual(plan['unixnu']['last_lba'], 62456575)
        self.assertEqual(plan['gap_before_rddata_bytes'], 1028096)
        self.assertEqual(result.h['count'], 128)
        self.assertEqual(len(result.entries), 98)
        self.assertFalse(plan['deployable'])
        self.assertFalse(plan['device_write_interface'])

    def test_all_unrelated_entries_and_mbr_are_exact(self):
        before_a, before_b = fixture(boot_flags=0x6f000000000008)
        a, b, _ = self.plan((before_a, before_b))
        self.assertEqual(a[:4096], before_a[:4096])
        before, after = gpt.GPT(before_a, before_b, 4096, sony.TOTAL), gpt.GPT(a, b, 4096, sony.TOTAL)
        for index in range(97):
            old = before.table[index * 128:(index + 1) * 128]
            new = after.table[index * 128:(index + 1) * 128]
            if index == 95:
                self.assertEqual(old[:40], new[:40])
                self.assertEqual(old[48:], new[48:])
            else:
                self.assertEqual(old, new)

    def test_fresh_boot_attributes_are_not_replaced_with_old_snapshot(self):
        for flags in [0, 8, 0x6f000000000008]:
            a, b, _ = self.plan(fixture(boot_flags=flags))
            result = gpt.GPT(a, b, 4096, sony.TOTAL)
            self.assertEqual(next(e for e in result.entries if e['index'] == 68)['flags'], flags)

    def test_wrong_geometry_rejected(self):
        a, b = fixture()
        for sector, total in [(512, sony.TOTAL), (4096, sony.TOTAL - 1)]:
            with self.assertRaisesRegex(ValueError, 'geometry'):
                sony.plan(a, b, sector, total, 64 << 30, gpt)

    def test_wrong_disk_or_userdata_identity_rejected(self):
        for kwargs in [{'disk_guid': str(uuid.uuid4())}, {'user_guid': str(uuid.uuid4())}]:
            with self.assertRaisesRegex(ValueError, 'identity'):
                self.plan(fixture(**kwargs))

    def test_changed_tail_bounds_rejected(self):
        for kwargs in [{'user_end': sony.USER_END - 1}, {'rd_start': sony.RDATA_START + 1}]:
            with self.assertRaises(ValueError):
                self.plan(fixture(**kwargs))

    def test_undeclared_nonzero_padding_rejected(self):
        with self.assertRaisesRegex(ValueError, 'padding'):
            self.plan(fixture(padding=True))

    def test_bad_crcs_rejected(self):
        a, b = fixture()
        for offset in [4096 + 16, 8192 + 30]:
            changed = bytearray(a)
            changed[offset] ^= 1
            with self.assertRaises(ValueError):
                self.plan((bytes(changed), b))

    def test_backup_disagreement_rejected(self):
        a, b = fixture()
        _, other = fixture(boot_flags=1)
        with self.assertRaises(ValueError):
            self.plan((a, other))

    def test_existing_unixnu_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unixnu'):
            self.plan(fixture(existing_unixnu=True))

    def test_duplicate_or_zero_new_guid_rejected(self):
        for value in [uuid.UUID(int=0), uuid.UUID(sony.USER_GUID), 'not-a-guid']:
            with self.assertRaisesRegex(ValueError, 'GUID'):
                self.plan(new_guid=value)

    def test_other_partition_sizes_not_implicitly_authorized(self):
        a, b = fixture()
        for requested in [0, 32 << 30, (64 << 30) + 4096, 256 << 30]:
            with self.assertRaisesRegex(ValueError, 'exactly 64'):
                sony.plan(a, b, 4096, sony.TOTAL, requested, gpt)


if __name__ == '__main__':
    unittest.main()
