import importlib.util
from pathlib import Path
import struct
import unittest

DEVICE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('qemu_source_block', DEVICE / 'scripts/ci/build-qemu-source-block.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
caller_spec = importlib.util.spec_from_file_location('qemu_storage_caller',
                                                    DEVICE / 'scripts/ci/prepare-qemu-storage-caller.py')
caller = importlib.util.module_from_spec(caller_spec)
caller_spec.loader.exec_module(caller)


class QemuSourceBlockTests(unittest.TestCase):
    def test_bsd_caller_is_conditional_and_refuses_duplicate_insertion(self):
        source = 'before\n\tvfsinit();\nafter\n'
        changed = caller.inject(source)
        self.assertIn('#if defined(XNU_QEMU_SOURCE_BLOCK) && XNU_QEMU_SOURCE_BLOCK', changed)
        self.assertEqual(changed.count('\tnative_qemu_storage_start();'), 1)
        self.assertLess(changed.index('vfsinit();'), changed.index('native_qemu_storage_start();'))
        for invalid in (changed, source + caller.MARKER, 'missing marker'):
            with self.assertRaisesRegex(ValueError, 'one unmodified'):
                caller.inject(invalid)

    def test_class_initializers_are_checked_by_section_not_just_symbol(self):
        header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0x80000002, 1, 1, 152, 0, 0)
        segment = struct.pack('<II16s4Q4I', 0x19, 152, b'\0' * 16, 0, 8, 184, 8, 7, 7, 1, 0)

        def section(name, size):
            return struct.pack('<16s16sQQ8I', name, b'__DATA', 0, size, 184, 3, 0, 0, 0, 0, 0, 0)

        self.assertTrue(builder.has_module_initializers(header + segment + section(b'__mod_init_func', 8)))
        self.assertFalse(builder.has_module_initializers(header + segment + section(b'__mod_init_func', 0)))
        self.assertFalse(builder.has_module_initializers(header + segment + section(b'__data', 8)))

    def test_late_registration_preserves_cpp_class_spelling(self):
        text = '// prefix\n' + builder.REGISTRATION_MACRO + '\n// suffix\n'
        changed = builder.late_source(text)
        self.assertIn('OSDefineMetaClassWithInit(IOBlockStorageDevice, IOService, )', changed)
        self.assertIn('OSMetaClass("UniXNUBlockStorageDevice", native_source_storage_parent()', changed)
        self.assertTrue(changed.startswith('// prefix\n'))
        self.assertTrue(changed.endswith('\n// suffix\n'))
        for invalid in ('no registration', text + builder.REGISTRATION_MACRO):
            with self.assertRaisesRegex(ValueError, 'macro changed'):
                builder.late_source(invalid)

    def test_entire_reference_and_transport_dispatch_are_checked(self):
        original = [{'slot': i, 'name': f'base_{i}', 'pac': [1, 0, i, 1]} for i in range(190)]
        base = [dict(row) for row in original]
        concrete = [dict(row, name=f'transport_{row["slot"]}') for row in original]
        builder.validate_tables(original, base, concrete)
        with self.assertRaisesRegex(ValueError, 'method count'):
            builder.validate_tables(original, base[:-1], concrete)
        concrete[27]['pac'] = [1, 0, 999, 1]
        with self.assertRaisesRegex(ValueError, 'slot 27'):
            builder.validate_tables(original, base, concrete)
        concrete[27] = dict(original[27], name='___cxa_pure_virtual')
        with self.assertRaisesRegex(ValueError, 'abstract operation'):
            builder.validate_tables(original, base, concrete)

    def test_coordinator_is_opt_in_and_registers_after_original_family(self):
        source = (DEVICE / 'ci/qemu/SourceBlockStorage.cpp').read_text()
        self.assertIn('native-qemu-storage', source)
        self.assertIn('QEMU-only platform guard refused', source)
        self.assertLess(source.index('OSKextLoadKextWithIdentifier("com.apple.iokit.IOStorageFamily")'),
                        source.index('qemu_storage_base_init();'))
        self.assertLess(source.index('removeDrivers(personality, false)'),
                        source.index('qemu_storage_transport_init();'))
        self.assertLess(source.index('postModLoad(handle)'), source.index('addDrivers(drivers, true)'))
        self.assertIn('personality->setObject("IOClass", className)', source)
        self.assertNotIn('NativeUfs', source)


if __name__ == '__main__':
    unittest.main()
