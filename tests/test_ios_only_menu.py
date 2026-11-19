"""Read the active C config and check the new pre-UEFI Android / iOS-only policy."""
import ast
from pathlib import Path
import re
import tomllib
import unittest

DEVICE=Path(__file__).resolve().parents[1]
SOURCE=DEVICE.parent/'uefi-pdx234/Platforms/Sony/pdx234Pkg/Drivers/PdxConfigFsDxe/PdxConfigFs.c'


class IosOnlyMenu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=SOURCE.read_text()
        expression=re.search(r'STATIC CONST CHAR8 mConfig\[\]\s*=\s*(.*?);',cls.source,re.S).group(1)
        cls.text=''.join(ast.literal_eval(value) for value in re.findall(r'"(?:[^"\\]|\\.)*"',expression))
        cls.config=tomllib.loads(cls.text)

    def test_no_android_or_linux_entry(self):
        self.assertFalse(any(entry['id']=='android' or entry['type']=='linux' for entry in self.config['entry']))
        self.assertNotIn('Android/Image',self.source)
        self.assertNotIn('PrepareAndroidFiles',self.source)
        self.assertNotIn('PinInput',self.source)

    def test_ios_target_stays_disabled_until_payload_exists(self):
        ios=next(entry for entry in self.config['entry'] if entry['id']=='ios27')
        self.assertEqual(ios['type'],'xnu')
        self.assertEqual(ios['path'],'Payloads/kernel.macho')
        self.assertFalse(ios['enabled'])
        self.assertNotIn('default',self.config['boot'])

    def test_menu_waits_and_only_other_entries_are_power_actions(self):
        self.assertEqual(self.config['boot']['timeout'],-1)
        self.assertEqual({entry['action'] for entry in self.config['entry'] if entry['type']=='action'},{'reset','shutdown'})


if __name__=='__main__':
    unittest.main(verbosity=2)
