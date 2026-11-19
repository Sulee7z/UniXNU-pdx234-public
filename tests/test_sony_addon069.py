import struct
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci'))
from platform069.addon import append_trust,decode,encode,trust_modules,valid_name


class Addon069(unittest.TestCase):
    def test_roundtrip_preserves_signed_bytes_and_modes(self):
        rows={'addons/a':dict(data=b'abc',mode=0o755),'xpc/launchd.plist':dict(data=b'data'*32,mode=0o644)}
        self.assertEqual(decode(encode(rows)),rows)

    def test_real_consumer_path_limit_and_traversal_policy(self):
        self.assertEqual(valid_name('a'*159),b'a'*159)
        for name in ['a'*160,'a..b','a/../b','/private/a','a\\b','a\0b','a//b','a/./b']:
            with self.subTest(name=name),self.assertRaises(ValueError):valid_name(name)

    def test_decode_rejects_bounds_trailing_duplicate_and_wrong_mode(self):
        encoded=encode({'addons/a':dict(data=b'x',mode=0o755)})
        for corrupt in [encoded[:-1],encoded+b'x',encoded[:16]+struct.pack('<Q',len(encoded)+1)+encoded[24:]]:
            with self.assertRaises(ValueError):decode(corrupt)
        raw=bytearray(encoded);struct.pack_into('<I',raw,28,0o4755)
        with self.assertRaises(ValueError):decode(bytes(raw))
        duplicate=bytearray(encoded+encoded[24:]);struct.pack_into('<I',duplicate,8,2);struct.pack_into('<Q',duplicate,16,len(duplicate))
        with self.assertRaises(ValueError):decode(bytes(duplicate))

    def test_trust_append_keeps_every_existing_module(self):
        module=struct.pack('<I16sI',2,b'x'*16,1)+bytes.fromhex('11'*20)+b'\x02\0\0\0'
        before=struct.pack('<II',1,8)+module
        after=append_trust(before,['22'*20,'11'*20,'22'*20]);modules=trust_modules(after)
        self.assertEqual(modules[0],module);self.assertEqual(len(modules),2)
        self.assertEqual(struct.unpack_from('<I',modules[1],20)[0],2)
        self.assertEqual(append_trust(before,[]),before)
        for value in ['1234','z'*40,'11'*21]:
            with self.subTest(value=value),self.assertRaises(ValueError):append_trust(before,[value])


if __name__=='__main__':unittest.main()
