import importlib.util
from pathlib import Path
import struct
import unittest

DEVICE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('d27_block_interface',
                                             DEVICE / 'scripts/ci/audit-d27-block-interface.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def reference_object(relocation_type=11, subtype=0x80000002):
    names = [b'__ZTV20IOBlockStorageDevice', b'_method_a', b'_method_b', b'_end']
    strings = bytearray(b'\0')
    indices = []
    for name in names:
        indices.append(len(strings))
        strings += name + b'\0'
    fileoff = 32 + 152 + 24
    relocoff = fileoff + 40
    symoff = relocoff + 16
    stroff = symoff + 64
    header = struct.pack('<8I', 0xfeedfacf, 0x100000c, subtype, 1, 2, 176, 0, 0)
    segment = struct.pack('<II16s4Q4I', 0x19, 152, b'\0' * 16, 0, 40, fileoff, 40, 7, 7, 1, 0)
    section = struct.pack('<16s16sQQ8I', b'__const', b'__DATA_CONST', 0, 40, fileoff, 3,
                          relocoff, 2, 0, 0, 0, 0)
    command = struct.pack('<6I', 2, 24, symoff, 4, stroff, len(strings))
    payload = bytes(16) + struct.pack('<2Q', (1 << 63) | (1 << 48) | (0x1234 << 32),
                                    (1 << 63) | (1 << 48) | (0x5678 << 32)) + bytes(8)
    relocations = b''.join(struct.pack('<II', offset, symbol | (3 << 25) | (1 << 27) |
                                     (relocation_type << 28)) for offset, symbol in ((16, 1), (24, 2)))
    symbols = b''.join(struct.pack('<IBBHQ', index, kind, section_number, 0, address)
                       for index, kind, section_number, address in (
                           (indices[0], 0xf, 1, 0), (indices[1], 1, 0, 0),
                           (indices[2], 1, 0, 0), (indices[3], 0xe, 1, 40)))
    return header + segment + section + command + payload + relocations + symbols + strings


class D27BlockInterfaceTests(unittest.TestCase):
    def test_arm64e_object_pac_relocations_and_trailing_null(self):
        rows = audit.object_vtable(reference_object(), '__ZTV20IOBlockStorageDevice')
        self.assertEqual([row['name'] for row in rows], ['_method_a', '_method_b'])
        self.assertEqual(rows[0]['pac'], (1, 0, 0x1234, 1))
        self.assertEqual(rows[1]['pac'], (1, 0, 0x5678, 1))

    def test_plain_arm64_is_not_an_arm64e_reference(self):
        with self.assertRaisesRegex(ValueError, 'arm64e'):
            audit.object_vtable(reference_object(subtype=0), '__ZTV20IOBlockStorageDevice')

    def test_plain_pointer_relocation_is_not_authenticated(self):
        with self.assertRaisesRegex(ValueError, 'Unauthenticated'):
            audit.object_vtable(reference_object(relocation_type=0), '__ZTV20IOBlockStorageDevice')

    def test_missing_symbols_and_truncated_inputs_fail(self):
        with self.assertRaisesRegex(ValueError, 'Missing or ambiguous'):
            audit.object_vtable(reference_object(), '__ZTVAnotherClass')
        for data in (b'', reference_object()[:100], reference_object()[:-2]):
            with self.assertRaises((ValueError, struct.error)):
                audit.object_vtable(data, '__ZTV20IOBlockStorageDevice')


if __name__ == '__main__':
    unittest.main()
