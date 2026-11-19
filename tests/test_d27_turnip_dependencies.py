"""Resolver cases that distinguish weak references, aliases and library reexports."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('audit', Path(__file__).resolve().parents[1]/'scripts/ci/audit-d27-turnip-dependencies.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class DependencyTests(unittest.TestCase):
    def test_export_trie_regular_and_alias(self):
        # Root edges to a direct symbol and an alias of a different exported name.
        data = bytes([0, 2])+b'_a\0'+bytes([10])+b'_b\0'+bytes([14])
        data += bytes([2, 0, 42, 0])
        terminal = bytes([8, 1])+b'_other\0'
        data += bytes([len(terminal)])+terminal+b'\0'
        found = audit.exports(data)
        self.assertEqual(found['_a'], {'flags': 0, 'address': 42})
        self.assertEqual(found['_b'], {'flags': 8, 'ordinal': 1, 'import_name': '_other'})

    def resolver(self):
        resolver = object.__new__(audit.Audit)
        resolver.loaded = {
            'A': {'exports': {'_alias': {'flags': 8, 'ordinal': 1, 'import_name': '_real'}},
                  'dependencies': [{'path': 'B'}], 'reexports': ['C']},
            'B': {'exports': {'_real': {'flags': 0, 'address': 1}}, 'reexports': []},
            'C': {'exports': {'_forwarded': {'flags': 0, 'address': 2}}, 'reexports': ['A']},
        }
        return resolver

    def test_alias_and_whole_library_reexport(self):
        resolver = self.resolver()
        self.assertEqual(resolver.resolve('A', '_alias')['provider'], 'B')
        self.assertEqual(resolver.resolve('A', '_forwarded')['provider'], 'C')
        self.assertIsNone(resolver.resolve('A', '_absent'))

    def test_missing_metadata_is_not_missing_symbol(self):
        resolver = self.resolver()
        del resolver.loaded['B']
        with self.assertRaises(KeyError):
            resolver.resolve('A', '_alias')

    def test_reexport_without_rename_keeps_requested_name(self):
        resolver = self.resolver()
        resolver.loaded['A']['exports']['_real'] = {'flags': 8, 'ordinal': 1, 'import_name': ''}
        self.assertEqual(resolver.resolve('A', '_real')['symbol'], '_real')

    def test_trie_cycle_is_rejected(self):
        with self.assertRaises(AssertionError):
            audit.exports(b'\x00\x01a\x00\x00')


if __name__ == '__main__':
    unittest.main()
