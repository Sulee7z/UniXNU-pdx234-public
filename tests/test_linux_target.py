"""Selected OS profile, not a hardcoded iOS17 value, controls the Linux cross target."""
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, '/mnt/g/UniXNU-Port/references/xperia-mainline-20261107/scripts')
from unixnu.kernel import linux_env
from unixnu.util import Error


class LinuxTarget(unittest.TestCase):
    def settings(self, profile):
        context = SimpleNamespace(tree=Path('/root/unixnu-build/pdx234-target-test'), board={'os': profile})
        with patch.dict(os.environ, {'UNIXNU_TOOLCHAIN': '/root/unixnu-toolchain'}):
            return linux_env(context)

    def test_arm64e27(self):
        result = self.settings({'arch': 'arm64e', 'ios_version': '27.0'})
        self.assertEqual(result['DARWIN_TRIPLE'], 'arm64e-apple-ios27.0')
        self.assertEqual(result['UNIXNU_SDK_VERSION'], '27.0')
        self.assertIn('-fptrauth-function-pointer-type-discrimination', result['CROSS_EXTRA_FLAGS'])

    def test_arm64_compatibility(self):
        result = self.settings({})
        self.assertEqual(result['DARWIN_TRIPLE'], 'arm64-apple-ios17.0')
        self.assertNotIn('-fptrauth-function-pointer-type-discrimination', result['CROSS_EXTRA_FLAGS'])

    def test_bad_profile_rejected(self):
        with self.assertRaises(Error):
            self.settings({'arch': 'arm64e', 'ios_version': '27.unknown'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
