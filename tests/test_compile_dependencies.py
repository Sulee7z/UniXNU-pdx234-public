import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('dependencies', Path(__file__).resolve().parents[1] / 'ci/compile_dependencies.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class Dependencies(unittest.TestCase):
    def test_legacy_receipt_is_not_reusable(self):
        self.assertFalse(MOD.valid({'exit': 0, 'source_sha256': 'unchanged'}))

    def test_real_compiler_tracks_transitive_system_and_spaced_paths(self):
        compiler = shutil.which('clang')
        if not compiler:
            self.skipTest('clang required')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            headers = root / 'system headers'
            headers.mkdir()
            inner = headers / 'inner.h'
            inner.write_text('#define VALUE 7\n')
            (headers / 'outer.h').write_text('#include "inner.h"\n')
            source = root / 'main.c'
            source.write_text('#include <outer.h>\nint value(void) { return VALUE; }\n')
            deps = root / 'main.d'
            subprocess.run([compiler, '-c', str(source), '-isystem', str(headers),
                            '-o', str(root / 'main.o'), '-MD', '-MF', str(deps),
                            '-MT', 'pdx_object'], check=True, capture_output=True)
            receipt = MOD.capture(deps, root, compiler)
            self.assertTrue(MOD.valid(receipt))
            self.assertIn(str(inner), receipt['dependencies'])
            inner.write_text('#define VALUE 9\n')
            self.assertFalse(MOD.valid(receipt))
            inner.unlink()
            self.assertFalse(MOD.valid(receipt))

    def test_archive_runner_records_actual_compilation(self):
        compiler = shutil.which('clang')
        if not compiler:
            self.skipTest('clang required')
        import json
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'unit.c'
            source.write_text('int value(void) { return 5; }\n')
            output = root / 'unit.o'
            MOD.run_recorded([compiler, '-c', source, '-o', output],
                             cwd=root, check=True, capture_output=True)
            receipt = json.loads((root / 'unit.o.dependencies.json').read_text())
            self.assertTrue(MOD.valid(receipt))
            self.assertEqual(receipt['object_sha256'], MOD.digest(output))
            source.write_text('int value(void) { return 6; }\n')
            self.assertFalse(MOD.valid(receipt))


if __name__ == '__main__':
    unittest.main()
