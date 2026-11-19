"""Regression checks for carrier build provenance and the read-only observer."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('d27_carrier', ROOT/'scripts/ci/build-d27-owner-cache-carrier.py')
carrier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(carrier)
OWNER_SPEC = importlib.util.spec_from_file_location('d27_owner_runner', ROOT/'scripts/ci/run-d27-owner-root.py')
owner = importlib.util.module_from_spec(OWNER_SPEC)
OWNER_SPEC.loader.exec_module(owner)
JOP_SPEC = importlib.util.spec_from_file_location('d27_native_jop', ROOT/'scripts/ci/build-d27-native-jop-key.py')
jop = importlib.util.module_from_spec(JOP_SPEC)
JOP_SPEC.loader.exec_module(jop)


class CarrierTests(unittest.TestCase):
    def recipe(self):
        return {'file': '/xnu/bsd/vm/vm_unix.c', 'arguments': [
            'clang', '-xc', '/xnu/bsd/vm/vm_unix.c', '-o', '/obj/vm_unix.o', '-c',
            '--target=arm64e-apple-ios27.0', '-D', 'VM_UNSAFE_TYPES',
            '-D', 'XNU_OWNER_CACHE_CARRIER=0', '-DXNU_OWNER_CACHE_CARRIER_WRONG_UUID=0',
            '-include', 'meta_features.h', '-I', '.', '-I', '/obj/EXPORT_HDRS/osfmk',
            '-MMD', '-MF', '/obj/vm_unix.d']}

    def test_private_abi_and_include_order_retained(self):
        command = carrier.compile_record(self.recipe(), Path('/new/vm_unix.c'), Path('/new/vm_unix.o'))
        self.assertIn('VM_UNSAFE_TYPES', command)
        self.assertIn('--target=arm64e-apple-ios27.0', command)
        self.assertEqual([command[i+1] for i, arg in enumerate(command) if arg == '-I'],
                         ['.', '/obj/EXPORT_HDRS/osfmk'])
        self.assertIn('XNU_OWNER_CACHE_CARRIER=1', command)
        self.assertNotIn('XNU_OWNER_CACHE_CARRIER=0', command)
        self.assertNotIn('-MMD', command)
        self.assertNotIn('/obj/vm_unix.d', command)

    def test_negative_control_keeps_real_target_inputs(self):
        command = carrier.compile_record(self.recipe(), Path('/new/vm_unix.c'), Path('/new/vm_unix.o'), True)
        self.assertIn('-DXNU_OWNER_CACHE_CARRIER_WRONG_UUID=1', command)
        self.assertIn('-DD27_OWNER_ROOT_UUID="'+carrier.ROOT_UUID+'"', command)
        self.assertIn('-DD27_OWNER_CACHE_UUID="'+carrier.CACHE_UUID+'"', command)

    def test_only_vm_object_changes(self):
        paths = ['/startup/bsd_init.o', '/startup/kern_exec.o', '/startup/IOKitBSDInit.cpo',
                 '/obj/bsd/DEVELOPMENT/vm_unix.o']
        updated = carrier.replace_vm_object(paths, Path('/carrier/vm_unix.o'))
        self.assertEqual(updated[:3], paths[:3])
        self.assertEqual(paths[-1], '/obj/bsd/DEVELOPMENT/vm_unix.o')
        self.assertEqual(updated[-1], '/carrier/vm_unix.o')

    def test_ambiguous_or_missing_vm_object_refused(self):
        for paths in [[], ['/a/bsd/DEVELOPMENT/vm_unix.o', '/b/bsd/DEVELOPMENT/vm_unix.o']]:
            with self.assertRaisesRegex(ValueError, 'Ambiguous'):
                carrier.replace_vm_object(paths, Path('/carrier/vm_unix.o'))

    def test_missing_recorded_carrier_defines_refused(self):
        record = self.recipe()
        record['arguments'].remove('-DXNU_OWNER_CACHE_CARRIER_WRONG_UUID=0')
        with self.assertRaisesRegex(ValueError, 'define missing'):
            carrier.compile_record(record, Path('/new/vm_unix.c'), Path('/new/vm_unix.o'))

    def test_no_duplicate_boot_manifest_implementation(self):
        source = (ROOT/'ci/qemu/SourceBlockStorage.cpp').read_text()
        self.assertNotIn('native_owner_publish_boot_manifest', source)
        runner = (ROOT/'scripts/ci/run-d27-owner-root.py').read_text()
        self.assertNotIn("codec.put(chosen,'boot-manifest-hash'", runner)
        self.assertNotIn('owner-dyld-cache-state', runner)


class LaunchdMainTests(unittest.TestCase):
    def setUp(self):
        base = ROOT/'out/test-d27-launchd-command-parser'
        base.mkdir(parents=True, exist_ok=True)
        work = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(work.cleanup)
        self.image = Path(work.name)/'launchd'

    def make_image(self, entries=(64,), subtype=2):
        commands = b''.join(struct.pack('<IIQQ', 0x80000028, 24, entry, 0) for entry in entries)
        header = struct.pack('<8I', 0xfeedfacf, 0x100000c, subtype, 2, len(entries), len(commands), 0, 0)
        self.image.write_bytes(header+commands+bytes(128))

    def test_unique_main_entry(self):
        self.make_image()
        self.assertEqual(owner.launchd_main_offset(self.image), 64)

    def test_non_arm64e_refused(self):
        self.make_image(subtype=0)
        with self.assertRaisesRegex(ValueError, 'arm64e'):
            owner.launchd_main_offset(self.image)

    def test_duplicate_main_refused(self):
        self.make_image(entries=(96, 96))
        with self.assertRaisesRegex(ValueError, 'one bounded'):
            owner.launchd_main_offset(self.image)

    def test_unaligned_or_out_of_file_main_refused(self):
        for entry in (65, 4096):
            self.make_image(entries=(entry,))
            with self.assertRaisesRegex(ValueError, 'one bounded'):
                owner.launchd_main_offset(self.image)


class NativeJopTests(unittest.TestCase):
    def test_reuses_only_upstream_hunk(self):
        original = ('uint64_t\nml_default_jop_pid(void)\n{\n#if HAS_PARAVIRTUALIZED_PAC\n'
                    '\tvmapple_pac_get_default_keys();\n\treturn vmapple_default_jop_pid;\n'
                    '#else\n\treturn 0;\n#endif\n}\n')
        adapted = jop.apply_hunk(original, jop.UPSTREAM.read_text())
        self.assertIn('#elif HAS_NATIVE_PAC\n', adapted)
        self.assertIn('\treturn 1;\n#else\n\treturn 0;', adapted)
        self.assertEqual(adapted.count('return 1;'), 1)
        with self.assertRaisesRegex(ValueError, 'Missing-hunk assumption'):
            jop.apply_hunk(adapted, jop.UPSTREAM.read_text())

    def test_replay_preserves_native_pac_configuration(self):
        record = {'file': '/xnu/machine_routines_apple.c', 'arguments': [
            'clang', '-c', '/xnu/machine_routines_apple.c', '-o', '/obj/original.o',
            '--target=arm64e-apple-ios27.0', '-include', 'meta_features.h',
            '-D', 'ARM64_BOARD_CONFIG_BCM2837', '-I', '/private', '-MMD', '-MF', '/obj/original.d']}
        command = jop.replay(record, Path('/new/source.c'), Path('/new/output.o'))
        self.assertIn('--target=arm64e-apple-ios27.0', command)
        self.assertIn('ARM64_BOARD_CONFIG_BCM2837', command)
        self.assertEqual(command[command.index('-include')+1], 'meta_features.h')
        self.assertEqual(command[command.index('-I')+1], '/private')
        self.assertNotIn('/obj/original.d', command)


if __name__ == '__main__':
    unittest.main()
