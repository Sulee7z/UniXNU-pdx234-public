"""Ensure analysis normalization never erases an authentication operation."""
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, '/mnt/e/UniXNU-sheng27-sony-20261113/strict-pac-abi-019/XnuPrelink')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci'))
from graphics_shape import shape


class GraphicsShapeTests(unittest.TestCase):
    def encode(self, words):
        return struct.pack('<'+'I'*len(words), *words)

    def test_auth_modifier_register_preserved(self):
        check=[0xaa1003f1,0xdac147f1,0xeb11021f,0x54000040,0xd4388e40]
        for modifier in (8,17,20,24):
            auth=0xdac11810 | modifier << 5
            self.assertEqual(shape(self.encode([auth,*check,0xd65f03c0]),0),
                             (auth,0xd65f03c0))
        self.assertNotEqual(shape(self.encode([0xdac11910,*check,0xd65f03c0]),0),
                            shape(self.encode([0xdac11a30,*check,0xd65f03c0]),0))

    def test_incomplete_or_changed_check_stays(self):
        check=[0xaa1003f1,0xdac147f1,0xeb11021f,0x54000040,0xd4388e40]
        for index in range(len(check)):
            changed=check.copy();changed[index]^=1
            result=shape(self.encode([0xdac11a30,*changed,0xd65f03c0]),0)
            self.assertTrue(result is None or len(result)>2)

    def test_branch_into_check_is_refused(self):
        words=[0x14000002,0xdac11a30,0xaa1003f1,0xdac147f1,0xeb11021f,0x54000040,0xd4388e40,0xd65f03c0]
        self.assertIsNone(shape(self.encode(words),0))

    def test_entry_bti_only(self):
        self.assertEqual(shape(self.encode([0xd503245f,0xd5033f9f,0xd65f03c0]),0),
                         (0xd5033f9f,0xd65f03c0))
        self.assertIn(0xd503245f,shape(self.encode([0xd5033f9f,0xd503245f,0xd65f03c0]),0))


if __name__=='__main__':unittest.main()
