"""Do not transfer identities using only layout, shared shapes or panic strings."""
import importlib.util
from pathlib import Path
import unittest
import tempfile

SCRIPT=Path(__file__).resolve().parents[1]/'scripts/check-d27-abi-fixture.py'
spec=importlib.util.spec_from_file_location('check_d27',SCRIPT)
checker=importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class RecoveryTests(unittest.TestCase):
    def test_source_fixture_pin_ignores_line_endings_but_not_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture.json'
            path.write_bytes(b'{\n  "name": "api"\n}\n')
            expected=checker.text_sha256(path)
            path.write_bytes(b'{\r\n  "name": "api"\r\n}\r\n')
            self.assertEqual(checker.text_sha256(path),expected)
            path.write_bytes(b'{\r\n  "name": "wrong"\r\n}\r\n')
            self.assertNotEqual(checker.text_sha256(path),expected)

    def inputs(self):
        entry={'original':'0x1000','original_size':40,'original_sha256':'raw-d27',
               'native_symbol':'_api','evidence':'Unique shape of reviewed J820 0x2000; see recovery.'}
        left={0x1000:{'size':40,'sha256':'raw-d27','shape_sha256':'shape','strings':['api']}}
        right={0x2000:{'size':40,'sha256':'raw-j820','shape_sha256':'shape','strings':['api']}}
        fixture={'functions':[{'original':'0x2000','original_sha256':'raw-j820','native_symbol':'_api'}]}
        return entry,left,{'shape':[0x1000]},right,{'shape':[0x2000]},fixture

    def test_unique_full_code_transfer_checks_both_raw_digests(self):
        values=self.inputs()
        self.assertEqual(checker.check_recovery(*values),'unique-pinned-code-and-strings')
        values[3][0x2000]['sha256']='changed'
        with self.assertRaisesRegex(ValueError,'Reference function digest'):
            checker.check_recovery(*values)

    def test_shared_shapes_and_changed_strings_are_rejected(self):
        values=self.inputs()
        values[2]['shape'].append(0x1004)
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            checker.check_recovery(*values)
        values=self.inputs()
        values[3][0x2000]['strings']=['different consumer']
        with self.assertRaisesRegex(ValueError,'strings changed'):
            checker.check_recovery(*values)

    def test_symbol_name_does_not_override_reviewed_provenance(self):
        values=self.inputs()
        values[0]['native_symbol']='_unrelated'
        with self.assertRaisesRegex(ValueError,'not in the reviewed fixture'):
            checker.check_recovery(*values)

    def test_manual_identity_requires_explicit_review_kind(self):
        values=self.inputs()
        values[0]['evidence']='Source ABI and disassembly, not a shared panic string.'
        with self.assertRaisesRegex(ValueError,'Missing cross-image provenance'):
            checker.check_recovery(*values)
        values[0]['verification']='source-and-disassembly'
        self.assertEqual(checker.check_recovery(*values),'source-and-disassembly')


if __name__=='__main__':unittest.main()
