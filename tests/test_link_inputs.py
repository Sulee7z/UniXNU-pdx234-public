import sys
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'ci'))
from link_inputs import collect_link_inputs


class LinkInputs(unittest.TestCase):
    def test_direct_trailing_files_and_linker_option_inputs(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for file in ('clang', 'first.o', 'version.o', 'libfirehose_kernel.a', 'libforced.a', 'alias.exp', 'section.bin'):
                (root/file).write_text(file)
            (root/'files').write_text(str(root/'first.o') + '\n')
            command = [str(root/'clang'), '-L'+str(root/'absent-directory'), '-filelist', str(root/'files'),
                       str(root/'version.o'), '-o', str(root/'new.macho'), str(root/'libfirehose_kernel.a'),
                       '-Wl,-force_load,'+str(root/'libforced.a'), '-Wl,-alias_list,'+str(root/'alias.exp'),
                       '-Wl,-sectcreate,__TEST,__data,'+str(root/'section.bin')]
            result = collect_link_inputs(command)
            self.assertEqual({p.name for p in result}, {'clang', 'files', 'first.o', 'version.o',
                'libfirehose_kernel.a', 'libforced.a', 'alias.exp', 'section.bin'})
            self.assertEqual(result[root/'libfirehose_kernel.a'], ['direct-input'])

    def test_missing_direct_input_is_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root/'clang').touch()
            with self.assertRaisesRegex(FileNotFoundError, 'version.o'):
                collect_link_inputs([str(root/'clang'), str(root/'version.o')])

    def test_static_search_and_duplicate_input_roles(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for file in ('clang', 'libtest.a'):
                (root/file).touch()
            command = [str(root/'clang'), '-L', str(root), '-ltest', str(root/'libtest.a')]
            self.assertEqual(collect_link_inputs(command)[root/'libtest.a'], ['direct-input', 'searched-library'])


if __name__ == '__main__':
    unittest.main()
