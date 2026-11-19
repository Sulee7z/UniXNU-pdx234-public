import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('d27_user_memory', ROOT/'ci/qemu/d27_user_memory.py')
memory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(memory)


class UserMemoryTests(unittest.TestCase):
    def setUp(self):
        self.mode = '0'
        self.ram = {}
        self.address = 0x2001234
        self.root = 0x4000800
        self.level2, self.level3, self.leaf = 0x5000000, 0x6000000, 0x7000000
        self.registers = {'TCR_EL1': 26 | (26 << 16) | (2 << 30),
                          'TTBR0_EL1': (2 << 48) | self.root}
        for table, shift, entry in [(self.root, 30, self.level2 | 3),
                                    (self.level2, 21, self.level3 | 3),
                                    (self.level3, 12, self.leaf | 3 | (1 << 10))]:
            self.put(table+((self.address >> shift) & 511)*8, entry.to_bytes(8, 'little'))
        self.payload = bytes(range(64))
        self.put(self.leaf+(self.address & 4095), self.payload)

    def put(self, address, data):
        self.ram.update({address+offset: value for offset, value in enumerate(data)})

    def packet(self, request):
        if request == 'qqemu.PhyMemMode':
            return self.mode
        if request.startswith('Qqemu.PhyMemMode:'):
            self.mode = request[-1]
            return 'OK'
        if request.startswith('m') and self.mode == '1':
            address, count = (int(value, 16) for value in request[1:].split(','))
            try:
                return bytes(self.ram[address+offset] for offset in range(count)).hex()
            except KeyError:
                return 'E14'
        return 'E14'

    def test_38bit_root_retains_2k_offset(self):
        capture = memory.read_user_memory(self.packet, self.registers, self.address, 64)
        self.assertEqual(capture['bytes'], self.payload.hex())
        self.assertEqual(capture['root_table'], hex(self.root))
        self.assertEqual(capture['root_alignment'], 2048)
        self.assertEqual(self.mode, '0')

    def test_47bit_user_root_uses_four_levels(self):
        self.registers['TCR_EL1'] = 17 | (26 << 16) | (2 << 30)
        level1 = 0x4800000
        self.put(self.root, (level1 | 3).to_bytes(8, 'little'))
        self.put(level1+((self.address >> 30) & 511)*8, (self.level2 | 3).to_bytes(8, 'little'))
        capture = memory.read_user_memory(self.packet, self.registers, self.address, 64)
        self.assertEqual(capture['bytes'], self.payload.hex())
        self.assertEqual([entry['level'] for entry in capture['translations'][0]['walk']], [0,1,2,3])
        self.assertEqual(capture['root_alignment'], 2048)
        self.assertEqual(self.mode, '0')

    def test_unmapped_page_is_recorded_and_mode_restored(self):
        self.put(self.root, bytes(8))
        capture = memory.read_user_memory(self.packet, self.registers, self.address, 64)
        self.assertFalse(capture['translations'][0]['mapped'])
        self.assertEqual(capture['bytes'], '')
        self.assertEqual(self.mode, '0')

    def test_read_error_restores_mode(self):
        self.ram.clear()
        with self.assertRaisesRegex(RuntimeError, 'Physical read unavailable'):
            memory.read_user_memory(self.packet, self.registers, self.address, 64)
        self.assertEqual(self.mode, '0')

    def test_invalid_user_pointer_is_not_stripped(self):
        with self.assertRaisesRegex(ValueError, 'untagged user VA'):
            memory.read_user_memory(self.packet, self.registers, 0x281e86727b0, 64)
        self.assertEqual(self.mode, '0')

    def test_kernel_pointer_view_uses_ttbr1_width(self):
        self.assertEqual(memory.kernel_pointer_view(0x99eff432d53b0840, self.registers['TCR_EL1']),
                          0xfffffff2d53b0840)

    def test_kernel_read_at_el0_uses_ttbr1_not_user_table(self):
        self.registers['TTBR1_EL1'] = (7 << 48) | self.root
        self.registers['TTBR0_EL1'] = 0xdead000
        address = ((1 << 64)-(1 << 38)) | self.address
        capture = memory.read_kernel_memory(self.packet, self.registers, address, 64)
        self.assertEqual(capture['bytes'], self.payload.hex())
        self.assertEqual(capture['source'], 'QEMU physical debugger reads through actual TTBR1')
        self.assertEqual(self.mode, '0')

    def test_kernel_read_failure_restores_debugger_mode(self):
        self.registers['TTBR1_EL1'] = self.root
        self.ram.clear()
        address = ((1 << 64)-(1 << 38)) | self.address
        with self.assertRaisesRegex(RuntimeError, 'Physical read unavailable'):
            memory.read_kernel_memory(self.packet, self.registers, address, 8)
        self.assertEqual(self.mode, '0')

    def test_kernel_reader_rejects_user_address(self):
        with self.assertRaisesRegex(ValueError, 'canonical kernel VA'):
            memory.read_kernel_memory(self.packet, self.registers, self.address, 8)

    def test_full_page_is_split_for_qemu_gdb_packet_limit(self):
        self.registers['TTBR1_EL1'] = self.root
        address = ((1 << 64)-(1 << 38)) | (self.address & ~4095)
        payload = bytes(range(256)) * 16
        self.put(self.leaf, payload)
        reads = []
        def bounded_packet(request):
            if request.startswith('m'):
                _, size = (int(v, 16) for v in request[1:].split(','))
                if size > 2048:
                    return 'E22'
                reads.append(size)
            return self.packet(request)
        capture = memory.read_kernel_memory(bounded_packet, self.registers, address, 4096)
        self.assertEqual(capture['bytes'], payload.hex())
        self.assertEqual(reads.count(1024), 4)
        self.assertEqual(self.mode, '0')

    def test_explicit_native_geometry_matches_actual_table_read(self):
        def physical(address,size):return bytes(self.ram[address+i] for i in range(size))
        raw=memory.read_native_pages(physical,self.root,self.address,64,bits=38,first_level=1)
        self.assertEqual(raw,self.payload)
        kernel_address=((1<<64)-(1<<38))|self.address
        self.assertEqual(memory.read_native_pages(physical,self.root,kernel_address,64,
            bits=38,first_level=1,kernel=True),self.payload)

    def test_explicit_native_root_rejects_wrong_geometry_and_missing_page(self):
        def physical(address,size):return bytes(self.ram[address+i] for i in range(size))
        with self.assertRaisesRegex(ValueError,'geometry'):
            memory.read_native_pages(physical,self.root,self.address,64,bits=47,first_level=1)
        self.put(self.root,bytes(8))
        with self.assertRaisesRegex(ValueError,'not resident'):
            memory.read_native_pages(physical,self.root,self.address,64,bits=38,first_level=1)


if __name__ == '__main__':
    unittest.main()
