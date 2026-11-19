"""Small local ZIPs test input identity/resume without fetching firmware."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('root_input_tools', ROOT / 'scripts/prepare-iphone14-root-inputs.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RootInputTests(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'out/test-root-inputs'
        base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.payload = b'AEA1' + bytes(range(256)) * 4
        self.zip_path = self.work / 'test.ipsw'
        with zipfile.ZipFile(self.zip_path, 'w', compression=zipfile.ZIP_STORED) as archive:
            archive.writestr('OS.dmg.aea', self.payload)
        self.stream = self.zip_path.open('rb')
        self.addCleanup(self.stream.close)
        self.archive = zipfile.ZipFile(self.stream)
        self.addCleanup(self.archive.close)
        entry = self.archive.getinfo('OS.dmg.aea')
        self.source = SimpleNamespace(
            zip=self.archive, stream=self.stream, spec='https://example.invalid/test.ipsw',
            info=lambda _: (entry.filename, entry.file_size, entry.compress_size))
        self.destination = self.work / 'OS.dmg.aea'

    def test_complete_extract_hashes(self):
        result = module.extract(self.source, 'OS', self.destination)
        self.assertEqual(self.destination.read_bytes(), self.payload)
        self.assertTrue(result['zip_crc_verified'])
        self.assertEqual(result['sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(result['sha384'], hashlib.sha384(self.payload).hexdigest())

    def prepare_partial(self, content):
        entry = self.archive.getinfo('OS.dmg.aea')
        identity = dict(component='OS', member=entry.filename, size=entry.file_size,
                        compressed_bytes=entry.compress_size, crc32=f'{entry.CRC:08x}',
                        url=self.source.spec, product='iPhone14,7', build='24A446')
        self.destination.with_suffix('.aea.origin.json').write_text(json.dumps(dict(identity=identity, completed=False)))
        self.destination.with_suffix('.aea.partial').write_bytes(content)

    def test_resume_stored_member(self):
        self.prepare_partial(self.payload[:512])
        result = module.extract(self.source, 'OS', self.destination)
        self.assertEqual(self.destination.read_bytes(), self.payload)
        self.assertEqual(result['sha256'], hashlib.sha256(self.payload).hexdigest())

    def test_changed_partial_is_preserved(self):
        self.prepare_partial(b'wrong partial prefix')
        with self.assertRaisesRegex(RuntimeError, 'prefix differs'):
            module.extract(self.source, 'OS', self.destination)
        self.assertEqual(self.destination.with_suffix('.aea.partial').read_bytes(), b'wrong partial prefix')

    def test_unidentified_existing_input_is_not_overwritten(self):
        self.destination.write_bytes(b'user input')
        with self.assertRaisesRegex(RuntimeError, 'Unidentified existing'):
            module.extract(self.source, 'OS', self.destination)
        self.assertEqual(self.destination.read_bytes(), b'user input')


if __name__ == '__main__':
    unittest.main()
