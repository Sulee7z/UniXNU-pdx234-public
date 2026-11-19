"""Keep a migrated build's sources and its historical naming evidence distinct."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

DEVICE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HandoffTests(unittest.TestCase):
    def test_rebase_generated_does_not_rewrite_compile_records_or_objects(self):
        try:
            module = load('resume_handoff', DEVICE / 'scripts/ci/resume-strict5-local.py')
        except ModuleNotFoundError as error:
            if error.name == 'fcntl':
                self.skipTest('POSIX-only build helper')
            raise
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('Makefile', 'link.filelist', 'file.d', 'command.json', 'file.o'):
                (root / name).write_text('/old/tree/source.c\n')
            changed = module.rebase_generated(root, '/old/tree', '/new/tree')
            self.assertEqual(sorted(changed), ['Makefile', 'file.d', 'link.filelist'])
            self.assertEqual((root / 'Makefile').read_text(), '/new/tree/source.c\n')
            self.assertEqual((root / 'command.json').read_text(), '/old/tree/source.c\n')
            self.assertEqual((root / 'file.o').read_text(), '/old/tree/source.c\n')

    def test_archived_names_have_no_native_addresses(self):
        record = json.loads((DEVICE / 'ci/strict5-reference-evidence/names.json').read_text())
        self.assertEqual(record['inputs']['kernelcache_sha256'],
                         'c28f4fc9b83cde00087e81f890c82d566b9e98b5ac228dfecd83afdf34070445')
        self.assertEqual(len(record['functions']), 154)
        self.assertEqual(record['data'], {})
        for entry in record['functions'].values():
            self.assertNotIn('native', entry)
            self.assertEqual(entry['addend'], 0)
            self.assertEqual(len(entry['original_sha256']), 64)
            self.assertIn(entry['how'], ('reference-symbol', 'reference-order'))
        importer = load('handoff_importer', DEVICE / 'scripts/ci/import-runner-identities.py')
        signature = importer.additive_reviewed_snapshot(DEVICE / 'ci/strict5-reference-evidence/kit',
                                                        DEVICE / 'ci/XnuPrelink')
        self.assertEqual(signature, record['matcher_signature'])

    def test_handoff_push_has_no_automatic_workflow_trigger(self):
        workflow = (DEVICE / '.github/workflows/package.yml').read_text().split('permissions:', 1)[0]
        self.assertIn('workflow_dispatch:', workflow)
        self.assertNotIn('\n  push:', workflow)
        self.assertNotIn('\n  pull_request:', workflow)


if __name__ == '__main__':
    unittest.main()
