import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pac_batch', ROOT / 'scripts/ci/build-d27-pac-abi-batch.py')
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)


class FlagOnly(unittest.TestCase):
    def replay(self, source='a.c', extra=()):
        args = ['clang', '--target=arm64e-apple-ios27.0', '-c', source, '-o', 'old.o', *extra]
        return batch.replay(args, Path(source), Path('new.o'))

    def test_single_compilation_flag(self):
        self.assertEqual(self.replay(), ['clang', '--target=arm64e-apple-ios27.0', '-c', 'a.c',
                                         '-o', 'new.o', batch.PAC_FLAG,
                                         '-Xclang', '-fptrauth-block-descriptor-pointers'])

    def test_existing_flag_not_duplicated(self):
        self.assertEqual(self.replay(extra=[batch.PAC_FLAG]).count(batch.PAC_FLAG), 1)

    def test_generated_iig_source_is_unchanged(self):
        result = self.replay('IOService.iig.cpp')
        self.assertIn('IOService.iig.cpp', result)
        self.assertNotIn('-iquote', result)
        self.assertFalse(hasattr(batch, 'patch_iig'))

    def test_assembly_is_unchanged(self):
        self.assertNotIn(batch.PAC_FLAG, self.replay('pac.S'))

    def test_pac_disabled_rejected(self):
        with self.assertRaises(ValueError):
            self.replay(extra=['-fno-ptrauth-calls'])

    def test_unqualified_target_rejected(self):
        with self.assertRaises(ValueError):
            batch.replay(['clang', '-c', 'a.c', '-o', 'old.o'], Path('a.c'), Path('new.o'))

    def test_later_conflicting_target_rejected(self):
        with self.assertRaises(ValueError):
            self.replay(extra=['--target=x86_64-unknown-linux-gnu'])

    def test_separate_target_spelling(self):
        result = batch.replay(['clang', '-target', 'arm64e-apple-ios27.0', '-c', 'a.c', '-o', 'old.o'],
                              Path('a.c'), Path('new.o'))
        self.assertIn(batch.PAC_FLAG, result)


if __name__ == '__main__':
    unittest.main()
