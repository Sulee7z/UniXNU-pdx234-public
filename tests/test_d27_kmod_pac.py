import importlib.util
from pathlib import Path
import struct
import unittest

path = Path(__file__).resolve().parents[1] / 'ci/d27_kmod_pac.py'
spec = importlib.util.spec_from_file_location('d27_kmod_pac', path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Native:
    def symbols(self):
        return {0x1000: ['_source_corecrypto14_start_once']}

    def read(self, address, size):
        return struct.pack('<4I', 0xF84B4268, 0xAA1303E0, 0xAA1403E1, 0xD63F091F) + bytes(size - 16)


class Cache:
    kmod = 0x4000
    pointer = (0x8000, 1, 0, 0xE4FE, 0)
    name = 'com.apple.kec.corecrypto'

    def fixups(self):
        return {self.kmod + 180: self.pointer, self.kmod + 188: self.pointer,
                self.kmod + 220: self.pointer}

    def read(self, address, size):
        if address == self.kmod + 8:
            return struct.pack('<I', 1)
        if address == self.kmod + 16:
            return self.name.encode().ljust(64, b'\0')
        return bytes(size)


class KmodPacTests(unittest.TestCase):
    def test_preserves_target_key_and_authentication(self):
        self.assertEqual(m.converted_pointer((0x1234, 1, 0, 0xE4FE, 0)), (0x1234, 1, 0, 0, 0))

    def test_rejects_other_pointer_schemas(self):
        for p in ((1, 0, 0, 0xE4FE, 0), (1, 1, 1, 0xE4FE, 0),
                  (1, 1, 0, 0, 0), (1, 1, 0, 0xE4FE, 1)):
            with self.assertRaises(ValueError):
                m.converted_pointer(p)

    def test_only_explicit_start_stop_sites(self):
        metadata = {'_PrelinkInfoDictionary': [dict(CFBundleIdentifier=Cache.name, _PrelinkKmodInfo=Cache.kmod)]}
        sites, records = m.entrypoint_sites(Cache(), metadata, {Cache.name}, Native())
        self.assertEqual(set(sites), {Cache.kmod + 180, Cache.kmod + 188})
        self.assertEqual([r['field'] for r in records], ['start', 'stop'])

    def test_rejects_wrong_record_identity(self):
        cache = Cache()
        cache.name = 'wrong'
        metadata = {'_PrelinkInfoDictionary': [dict(CFBundleIdentifier=Cache.name, _PrelinkKmodInfo=Cache.kmod)]}
        with self.assertRaises(ValueError):
            m.entrypoint_sites(cache, metadata, {Cache.name}, Native())

    def test_rejects_changed_native_call(self):
        native = Native()
        native.read = lambda address, size: bytes(size)
        with self.assertRaises(ValueError):
            m.entrypoint_sites(Cache(), {'_PrelinkInfoDictionary': []}, None, native)

    def test_allows_only_audited_d27_name_aliases(self):
        identifier = 'com.apple.driver.AppleARMWatchdogTimer'
        cache = Cache()
        cache.name = m.D27_KMOD_NAMES[identifier]
        metadata = {'_PrelinkInfoDictionary': [
            dict(CFBundleIdentifier=identifier, _PrelinkKmodInfo=Cache.kmod)]}
        # Alias check passes; refusal is only because this fixture omits corecrypto.
        with self.assertRaisesRegex(ValueError, 'corecrypto start fixup'):
            m.entrypoint_sites(cache, metadata, {identifier}, Native())


if __name__ == '__main__':
    unittest.main()
