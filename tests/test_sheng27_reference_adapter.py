"""Offline source/argv checks; no phone, no builds, no archive modifications."""
import ast
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sony_reference', ROOT / 'scripts/ci/build-sheng27-sony-reference.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

FIXTURE = '''import argparse
from pathlib import Path
def main():
    forced = []
    inputs = {
        'versions': {'UNIXNU_IOS_VERSION': '27.0'}
    }
    args = [
        f'CFLAGS_EXTRA={flags}',
        f'OBJROOT={output}/{mode}-obj',f'SYMROOT={output}/{mode}-sym',f'DSTROOT={output}/{mode}-dst']
    if stub_names:
        fabricate_stub()
    # Forced exports
    objects = linked_objects(output / f'{mode}-obj/RELEASE_ARM64_BCM2837', options.lto)
    for i in range(0, len(objects), 100):
        listed = subprocess.run(['xcrun', 'nm', '-gUj', *objects[i:i + 100]], capture_output=True, text=True, check=True)
'''


class ReferenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.host = ['LD=/host/local-lto-link.sh', 'HOST_CC=/host/xnu-host-cc', 'MIGCOM=/host/migcom']

    def test_adaptation_parses_and_preserves_required_host_argv(self):
        text = MOD.adapt_recipe(FIXTURE, self.host, Path('/tree/build/sheng-ufs/libShengUfs.a'))
        ast.parse(text)
        for arg in self.host:
            # One copy in the make argv and one in the cache provenance.
            self.assertEqual(text.count(repr(arg)), 2)
        self.assertIn('-march=armv8.5-a+lse', text)
        self.assertIn('-DXNU_NATIVE_CS_HASH_CACHE=1', text)
        self.assertEqual(text.count('forced.append('), 1)
        self.assertIn("'DARWIN_TRIPLE'", text)
        self.assertIn("'CROSS_EXTRA_FLAGS'", text)

    def test_no_synthetic_hook_or_missing_lto_fallback(self):
        text = MOD.adapt_recipe(FIXTURE, self.host, Path('/storage.a'))
        self.assertNotIn('fabricate_stub()', text)
        self.assertIn('Reference is missing real source hooks', text)
        self.assertIn('LTO did not emit its object', text)
        self.assertIn("'justlto.o').exists()", text)
        self.assertIn('listed.stderr', text)

    def test_each_invocation_uses_clean_input_without_accumulating_args(self):
        one = MOD.adapt_recipe(FIXTURE, self.host, Path('/storage.a'))
        self.assertEqual(one, MOD.adapt_recipe(FIXTURE, self.host, Path('/storage.a')))
        with self.assertRaises(ValueError):
            MOD.adapt_recipe(one, self.host, Path('/storage.a'))

    def test_unknown_source_structure_rejected(self):
        with self.assertRaises(ValueError):
            MOD.adapt_recipe(FIXTURE.replace('    inputs = {', '    changed_inputs = {'), self.host, Path('/storage.a'))

    def test_compiler_feature_macros_match_assembler_target(self):
        self.assertIn('-march=' + MOD.MARCH, MOD.FEATURE_FLAGS)
        for version in range(2, 6):
            self.assertIn('-D__ARM_ARCH_8_' + str(version) + '__=1', MOD.FEATURE_FLAGS)

    def test_per_object_pan_flags_do_not_override_dit_isa(self):
        text = MOD.adapt_recipe(FIXTURE + "\nPAN = '-march=armv8.1-a'\n", self.host, Path('/storage.a'))
        self.assertNotIn('-march=armv8.1-a', text)

    def test_sanitizer_runtime_is_real_object_not_generated_stub(self):
        source = FIXTURE.replace("        f'CFLAGS_EXTRA={flags}',",
            "        f'CFLAGS_EXTRA={flags}',\n"
            "        'LD_KERNEL_ARCHIVES='+' '.join([f'-L{sdk}/usr/local/lib/kernel','-lfirehose_kernel',\n"
            "                                        *map(str,archives),*(f'-Wl,-force_load,{p}' for p in forced)]),\n"
            "        'XNU_EXTERNAL_KERNEL_ARCHIVES='+' '.join(map(str,archives+forced)),")
        runtime = Path('/native/san/ubsan_minimal.o')
        adapted = MOD.adapt_recipe(source, self.host, Path('/storage.a'), runtime)
        self.assertIn(repr(str(runtime)), adapted)
        self.assertNotIn('native-stubs.c', adapted)

    def test_macho_platform_rejects_macos_even_with_arm64e(self):
        import struct
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.o'
            header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 2, 1, 1, 24, 0, 0)
            path.write_bytes(header + struct.pack('<6I', 0x32, 24, 1, 0, 0, 0))
            with self.assertRaises(ValueError):
                MOD.macho_identity(path, 1)
            path.write_bytes(header + struct.pack('<6I', 0x32, 24, 2, 0, 0, 0))
            self.assertEqual(MOD.macho_identity(path, 1)['platforms'], [2])


if __name__ == '__main__':
    unittest.main()
