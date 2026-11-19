import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci'))
from linux_iig import adapt_generated, AUTHENTICATED, FALLBACK


class LinuxIigCompatibility(unittest.TestCase):
    def test_authenticates_member_schema(self):
        result = adapt_generated(FALLBACK)
        self.assertEqual(result, AUTHENTICATED)
        self.assertIn('__ptrauth(0, 0, __builtin_ptrauth_type_discriminator(typeof(func)))', result)
        self.assertNotIn('xpaci', result)
        self.assertNotIn('__asm__', result)

    def test_non_pac_branch_is_retained(self):
        self.assertTrue(adapt_generated(FALLBACK).endswith(FALLBACK))

    def test_idempotent(self):
        self.assertEqual(adapt_generated(AUTHENTICATED), AUTHENTICATED)

    def test_unknown_generator_rejected(self):
        with self.assertRaises(ValueError):
            adapt_generated('different generator')


if __name__ == '__main__':
    unittest.main()
