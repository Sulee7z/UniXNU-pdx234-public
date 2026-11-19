"""Historical candidate007 Linux config; the active menu no longer boots Android."""
import ast
from pathlib import Path
import re
import subprocess
import tomllib
import unittest

DEVICE = Path(__file__).resolve().parents[1]
PROJECT = DEVICE.parents[1]
SOURCE = DEVICE.parent / 'uefi-pdx234/Platforms/Sony/pdx234Pkg/Drivers/PdxConfigFsDxe/PdxConfigFs.c'
FDT = PROJECT / 'evidence/Xperia-XQ-DQ72/20261107T092807Z/live.dtb'


def fragment(source, name):
    expression = re.search(r'STATIC CONST CHAR8 ' + name + r'\[\]\s*=\s*(.*?);', source, re.S).group(1)
    return ''.join(ast.literal_eval(value) for value in re.findall(r'"(?:[^"\\]|\\.)*"', expression))


class LinuxConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = subprocess.check_output(['git','-C',str(DEVICE.parent/'uefi-pdx234'),'show',
            '25c178d79fbbda894730a47be33c38a93b099053:Platforms/Sony/pdx234Pkg/Drivers/PdxConfigFsDxe/PdxConfigFs.c'],text=True)
        cls.prefix = fragment(cls.source, 'mConfigPrefix')
        cls.suffix = fragment(cls.source, 'mConfigSuffix')

    def config(self, args):
        return tomllib.loads(self.prefix + args.replace('\\', '\\\\').replace('"', '\\"') + self.suffix)

    def test_original_sony_bootargs_and_official_entry(self):
        args = subprocess.check_output(['fdtget', '-t', 's', str(FDT), '/chosen', 'bootargs'], text=True).rstrip('\n')
        config = self.config(args)
        android = next(entry for entry in config['entry'] if entry['id'] == 'android')
        self.assertEqual(android['type'], 'linux')
        self.assertEqual(android['path'], 'Android/Image')
        self.assertEqual(android['dtb'], 'Android/bootloader.dtb')
        self.assertEqual(android['initrd'], 'Android/initrd.img')
        self.assertEqual(android['args'], args)
        self.assertEqual(config['boot']['timeout'], -1)
        self.assertFalse(next(entry for entry in config['entry'] if entry['id'] == 'ios27')['enabled'])

    def test_quotes_and_backslashes_roundtrip(self):
        for args in ('', 'a="two words" path=a\\b', 'a=1  b=2 ', 'x=' + '"\\' * 100):
            with self.subTest(args=args):
                self.assertEqual(self.config(args)['entry'][0]['args'], args)

    def test_new_menu_does_not_select_manual_resume(self):
        self.assertNotIn('fv:61F1E287', self.prefix)
        self.assertNotIn('ExitBootServices(', self.source)
        self.assertNotIn('PdxAndroidEnter(', self.source)
        self.assertIn('gEfiDevicePathProtocolGuid,&mDevicePath', self.source)

    def test_capture_has_bounded_original_initrd(self):
        values = []
        for name in ('linux,initrd-start', 'linux,initrd-end'):
            cells = subprocess.check_output(['fdtget', '-t', 'x', str(FDT), '/chosen', name], text=True).split()
            values.append(int(''.join(f'{int(cell, 16):08x}' for cell in cells), 16))
        self.assertGreater(values[1], values[0])
        self.assertLess(values[1] - values[0], 128 << 20)


if __name__ == '__main__':
    unittest.main(verbosity=2)
