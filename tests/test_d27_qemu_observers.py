"""Exercise read-only observers against bounded kernel and task page tables."""
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/qemu'))
from d27_display_pm import capture_display_pm
from d27_thread_snapshot import capture


class GuestMemory:
    def __init__(self):
        self.ram, self.messages, self.mode = {}, [], '0'
        self.kroot, self.kl2, self.kl3, self.kpa = 0x4000800, 0x5000000, 0x6000000, 0x7000000
        self.base = (1 << 64) - (1 << 38) + 0x2000000
        self.uroot, self.ul1, self.ul2, self.ul3, self.upa = 0x8000800, 0x8100000, 0x8200000, 0x8300000, 0x8400000
        self.uv = 0x100008000
        self.registers = dict(TCR_EL1=17 | (26 << 16) | (2 << 30),
                              TTBR1_EL1=self.kroot, TTBR0_EL1=0xdead000)
        self.put_word(self.kroot + ((self.base >> 30) & 255) * 8, self.kl2 | 3)
        self.put_word(self.kl2 + ((self.base >> 21) & 511) * 8, self.kl3 | 3)
        for i in range(16):
            self.put_word(self.kl3 + (((self.base >> 12) + i) & 511) * 8,
                          self.kpa + i * 4096 | 3 | (1 << 10))
        for table, shift, target, mask in [(self.uroot, 39, self.ul1, 255),
                                           (self.ul1, 30, self.ul2, 511),
                                           (self.ul2, 21, self.ul3, 511),
                                           (self.ul3, 12, self.upa, 511)]:
            self.put_word(table + ((self.uv >> shift) & mask) * 8, target | 3 | (1 << 10) | (1 << 6))

    def put(self, pa, data):
        self.ram.update({pa + i: value for i, value in enumerate(data)})

    def put_word(self, pa, value):
        self.put(pa, value.to_bytes(8, 'little'))

    def write(self, va, data):
        self.put(self.kpa + va - self.base, data)

    def word(self, va, value, size=8):
        self.write(va, value.to_bytes(size, 'little'))

    @staticmethod
    def signed(va):
        return va & ((1 << 38) - 1) | 0x1234000000000000

    def packet(self, request):
        self.messages.append(request)
        if request == 'qqemu.PhyMemMode':
            return self.mode
        if request.startswith('Qqemu.PhyMemMode:'):
            self.mode = request[-1]
            return 'OK'
        if request.startswith('m') and self.mode == '1':
            address, size = (int(v, 16) for v in request[1:].split(','))
            try:
                return bytes(self.ram[address + i] for i in range(size)).hex()
            except KeyError:
                return 'E14'
        return 'E14'


class CurrentThreadSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PROCESS_PLAN:
            raise unittest.SkipTest('Supply --process-plan from the actual linked native DWARF')

    def setUp(self):
        self.plan = json.loads(Path(PROCESS_PLAN).read_text())
        self.guest = GuestMemory()
        g = self.guest
        self.address = {name: g.base + i * 4096 for i, name in enumerate(
            ['symbol', 'attr', 'proc', 'pro', 'task', 'map', 'pmap', 'thread', 'tro', 'state', 'region'], 1)}
        a, c, l, s = self.address, self.plan['process_layout'], self.plan['thread_snapshot_layout'], self.plan['saved_state_layout']
        self.plan['thread_snapshot_native_user_pt_attr'] = hex(a['symbol'])
        g.word(a['symbol'], g.signed(a['attr']))
        g.word(a['attr'] + l['attr_root'], 0, 4)
        g.word(a['attr'] + l['attr_shift'], 12)
        g.word(a['proc'] + l['proc_ro'], g.signed(a['pro']))
        g.word(a['pro'] + l['proc_ro_owner'], g.signed(a['proc']))
        g.word(a['pro'] + l['proc_ro_task'], g.signed(a['task']))
        g.write(a['task'], bytes(c['task_region'] + 8))
        for offset, value, width in [(l['task_threads'], g.signed(a['thread']), 8),
                                      (l['task_thread_count'], 1, 4),
                                      (l['task_map'], g.signed(a['map']), 8),
                                      (c['task_region'], g.signed(a['region']), 8)]:
            g.word(a['task'] + offset, value, width)
        g.word(a['map'] + l['map_pmap'], g.signed(a['pmap']))
        g.word(a['pmap'] + l['pmap_ttep'], g.uroot)
        g.word(a['region'] + c['region_slide'], 0x520000, 4)
        g.write(a['thread'], bytes(l['thread_id'] + 8))
        for offset, value, width in [(c['thread_ro'], g.signed(a['tro']), 8),
                                      (c['thread_user_state'], g.signed(a['state']), 8),
                                      (l['thread_id'], 101, 8), (l['thread_state'], 5, 4),
                                      (l['thread_link'], g.signed(a['task'] + l['task_threads']), 8)]:
            g.word(a['thread'] + offset, value, width)
        g.write(a['tro'], bytes(c['ro_task'] + 8))
        g.word(a['tro'] + c['ro_owner'], g.signed(a['thread']))
        g.word(a['tro'] + c['ro_task'], g.signed(a['task']))
        g.write(a['state'], struct.pack('<II', 21, 74) + bytes(s['bytes'] - 8))
        for key, value in [('pc', 0x180010000), ('lr', 0x180020000), ('fp', g.uv + 0x100), ('sp', g.uv)]:
            g.word(a['state'] + s[key], value)
        g.put(g.upa + 0x100, struct.pack('<QQ', 0, 0x1a0001234))
        self.processes = [dict(address=hex(a['proc']), name='SpringBoard', pid=30, state=2)]

    def snapshot(self):
        return capture(self.guest.packet, self.processes, self.plan, self.guest.registers)

    def test_authenticated_pointers_and_actual_task_table(self):
        row = self.snapshot()['processes'][0]
        self.assertTrue(row['complete'], row)
        item = row['threads'][0]
        self.assertEqual(item['user_pc'], '0x180010000')
        self.assertEqual(item['user_frames'][0]['lr'], '0x1a0001234')
        self.assertEqual(row['cache_slide'], 0x520000)
        self.assertTrue(item['user_stack_complete'])
        self.assertEqual(self.guest.mode, '0')
        self.assertFalse(any(v.startswith(('M', 'X', 'G', 'P')) for v in self.guest.messages))

    def test_owner_mismatch(self):
        self.guest.word(self.address['pro'], self.guest.signed(self.address['task']))
        self.assertIn('owner mismatch', self.snapshot()['processes'][0]['error'])

    def test_old_saved_state_header(self):
        self.guest.word(self.address['state'] + 4, 72, 4)
        item = self.snapshot()['processes'][0]['threads'][0]
        self.assertIn('saved-state header', item['snapshot_error'])
        self.assertNotIn('user_pc', item)

    def test_unmapped_user_stack_keeps_kernel_evidence(self):
        g = self.guest
        g.put_word(g.ul3 + ((g.uv >> 12) & 511) * 8, 0)
        item = self.snapshot()['processes'][0]['threads'][0]
        self.assertEqual(item['user_pc'], '0x180010000')
        self.assertIn('not resident', item['snapshot_error'])
        self.assertEqual(g.mode, '0')

    def test_queue_cycle_is_bounded(self):
        self.guest.word(self.address['thread'] + self.plan['thread_snapshot_layout']['thread_link'],
                        self.guest.signed(self.address['thread']))
        row = self.snapshot()['processes'][0]
        self.assertFalse(row['complete'])
        self.assertEqual(len(row['threads']), 1)

    def test_boot_geometry_does_not_match_user_root(self):
        self.guest.word(self.address['attr'] + self.plan['thread_snapshot_layout']['attr_root'], 1, 4)
        with self.assertRaisesRegex(ValueError, 'geometry differs'):
            self.snapshot()

    def test_unbound_user_geometry_is_rejected(self):
        del self.plan['thread_snapshot_native_user_pt_attr']
        with self.assertRaisesRegex(ValueError, 'native_user_pt_attr'):
            self.snapshot()


class CurrentPowerSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PM_PLAN:
            raise unittest.SkipTest('Supply --pm-plan from the actual linked native DWARF')

    def setUp(self):
        self.plan = json.loads(Path(PM_PLAN).read_text())
        self.guest = GuestMemory()
        g = self.guest
        self.symbol, self.display, self.pm = g.base + 0x1100, g.base + 0x1ff0, g.base + 0x3f10
        g.word(self.symbol, g.signed(self.display))
        service = self.plan['layouts']['IOService']
        g.write(self.display, bytes(service['bytes']))
        g.word(self.display + service['fields']['pwrMgt']['offset'], g.signed(self.pm))
        g.word(self.display + service['fields']['initialized']['offset'], 1, 1)
        pm = self.plan['layouts']['IOServicePM']
        g.write(self.pm, bytes(pm['bytes']))
        for name, value in [('MachineState', 6), ('HeadNotePowerState', 1), ('DesiredPowerState', 1),
                            ('NumberOfPowerStates', 2), ('MaxPowerState', 1),
                            ('ParentsCurrentPowerFlags', 1), ('ControllingDriver', self.display)]:
            field = pm['fields'][name]
            g.word(self.pm + field['offset'], value, field['bytes'])
        for name in ('InitialPowerChange', 'ParentsKnowState', 'DriverCallBusy'):
            field = pm['fields'][name]
            address = g.kpa + self.pm - g.base + field['offset']
            g.ram[address] |= 1 << field['bit']

    def snapshot(self):
        return capture_display_pm(self.guest.packet, self.guest.registers, self.symbol, self.plan)

    def test_pac_pointers_cross_page_and_flags(self):
        result = self.snapshot()
        self.assertTrue(result['complete'])
        self.assertEqual(result['object'], hex(self.display))
        self.assertEqual(result['pm_object'], hex(self.pm))
        for name in ('parents_know_state', 'driver_call_busy', 'desired_differs_from_current'):
            self.assertTrue(result['predicates'][name])
        self.assertEqual(self.guest.mode, '0')
        self.assertFalse(any(v.startswith(('M', 'X', 'G', 'P')) for v in self.guest.messages))

    def test_missing_display(self):
        self.guest.word(self.symbol, 0)
        result = self.snapshot()
        self.assertFalse(result['complete'])
        self.assertFalse(result['display_created'])

    def test_unreadable_pm_restores_mode(self):
        del self.guest.ram[self.guest.kpa + self.pm - self.guest.base]
        with self.assertRaises(RuntimeError):
            self.snapshot()
        self.assertEqual(self.guest.mode, '0')


PROCESS_PLAN = None
PM_PLAN = None
if __name__ == '__main__':
    for flag in ('--process-plan', '--pm-plan'):
        if flag in sys.argv:
            index = sys.argv.index(flag)
            if flag == '--process-plan':
                PROCESS_PLAN = sys.argv[index + 1]
            else:
                PM_PLAN = sys.argv[index + 1]
            del sys.argv[index:index + 2]
    unittest.main()
