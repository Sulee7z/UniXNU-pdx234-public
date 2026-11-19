from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci'))
from darwin_boot_args import validate


class DarwinArgumentBoundary(unittest.TestCase):
    def test_exact_boundary_reserves_terminator(self):
        result=validate('a'*1023)
        self.assertTrue(result['passed'])
        self.assertEqual(result['remaining_argument_bytes'],0)
        self.assertFalse(result['truncated'])

    def test_overflow_is_rejected_not_truncated(self):
        for count in (1024,1041,4096):
            with self.subTest(count=count),self.assertRaises(ValueError):validate('a'*count)

    def test_nonASCII_or_NUL_rejected(self):
        for value in ('test=\u0080','test=中文','test=1\0data-persist=2',None):
            with self.subTest(value=value),self.assertRaises(ValueError):validate(value)

    def test_empty_and_ASCII_DEL(self):
        self.assertEqual(validate('')['ascii_bytes'],0)
        self.assertEqual(validate('\x7f')['ascii_bytes'],1)


if __name__=='__main__':unittest.main()
