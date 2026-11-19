import struct
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ci/qemu'))
from d27_registry_memory import find_service


class RegistryReads(unittest.TestCase):
    def setUp(self):
        self.ram={};self.names={'_gIOServicePlane':0x1000,'__ZL13gRegistryRoot':0x1010}
        self.word(0x1000,0x2000);self.word(0x1010,0x3000);self.word(0x2020,0x1234)
        self.word(0x3000,0x1110);self.word(0x3018,0x4000)
        self.word(0x4014,1,4);self.word(0x4018,2,4);self.word(0x4020,0x5000)
        self.word(0x5000,0x1234);self.word(0x5008,0x6000)
        self.word(0x6014,2,4);self.word(0x6018,2,4);self.word(0x6020,0x7000)
        self.word(0x7000,0x8000);self.word(0x7008,0x9000)
        self.word(0x8000,0x2220);self.word(0x8018,0)
        self.word(0x9000,0x3330);self.word(0x9018,0)

    def word(self,address,value,width=8):
        self.ram.update({address+i:v for i,v in enumerate(value.to_bytes(width,'little'))})

    def read(self,address,size):return bytes(self.ram[address+i] for i in range(size))

    def test_exact_native_vtable_and_child_key(self):
        row=find_service(self.read,lambda x:x,self.names,0x2220)
        self.assertEqual(row['address'],0x8000)
        self.assertEqual(row['registry_entries_read'],3)

    def test_duplicate_service_is_rejected(self):
        self.word(0x9000,0x2220)
        with self.assertRaisesRegex(ValueError,'exactly one'):
            find_service(self.read,lambda x:x,self.names,0x2220)

    def test_bound_rejects_partial_traversal(self):
        with self.assertRaisesRegex(ValueError,'limit'):
            find_service(self.read,lambda x:x,self.names,0x2220,limit=1)

    def test_capacity_is_checked(self):
        self.word(0x6014,3,4)
        with self.assertRaisesRegex(ValueError,'children array'):
            find_service(self.read,lambda x:x,self.names,0x2220)


if __name__=='__main__':unittest.main()
