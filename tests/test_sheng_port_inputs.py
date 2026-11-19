"""Verify Sony facts replacing Sheng board values, without claiming driver runtime."""
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest

DEVICE=Path(__file__).resolve().parents[1]
PROJECT=DEVICE.parents[1]
sys.path.insert(0,str(PROJECT/'references/pdx234-mainline-20261108/scripts'))
from unixnu.devicetree import read_fdt, registers


def child(root,name):
    return next(n for n in root.children if n.name.split('@')[0]==name)


class SonyInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live=read_fdt((PROJECT/'evidence/Xperia-XQ-DQ72/20261107T092807Z/live.dtb').read_bytes())
        compiled=subprocess.check_output(['dtc','-I','dts','-O','dtb','-i',
            str(PROJECT/'references/pdx234-sm8550-20261108/dts'),str(DEVICE/'dts/pdx234.dts')])
        cls.board=read_fdt(compiled)
        cls.config=tomllib.loads((DEVICE/'board.toml').read_text())

    def test_memory_regions_match_nonzero_capture(self):
        expected=[region for region in registers(child(self.live,'memory')) if region[1]]
        self.assertEqual(registers(child(self.board,'memory')),expected)

    def test_identity_and_root_are_phone_not_sheng_ipad(self):
        self.assertIn(b'somc,pdx234-generic',self.board.properties['compatible'])
        self.assertEqual(self.config['board']['os_profile'],'ios-27.0.1-24A446-iphone14')
        self.assertEqual(self.config['payload']['adt']['root_match_volume_uuid'],'CA0FF65B-3E73-4D62-9000-EC719E1B6DB1')

    def test_example_marker_cleared_and_write_guards_remain(self):
        self.assertFalse(self.config['board'].get('example'))
        self.assertIn('native-ufs-root=0',self.config['payload']['kernel_args'])
        self.assertIn('sheng-data-persist=0',self.config['payload']['kernel_args'])
        self.assertNotIn('firmware',self.config)
        self.assertNotIn('bootimg',self.config)


if __name__=='__main__':
    unittest.main(verbosity=2)
