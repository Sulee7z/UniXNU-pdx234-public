import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci'))
from darwin_boot_args import validate
from sony_menu068 import shorten,REMOVED_DEFAULTS


class Menu068Fix(unittest.TestCase):
    def test_actual067_is_invalid_and_only_two_default_tokens_are_removed(self):
        old=json.loads((ROOT/'out/d27-pac-abi-release-20261118-067/release.json').read_text())['kernel_args']
        with self.assertRaises(ValueError):validate(old)
        new=shorten(old)
        self.assertEqual(validate(new)['ascii_bytes'],1006)
        self.assertEqual(new.split(),['build-tag=PDX068' if value=='build-tag=PDX067' else value
            for value in old.split() if value not in REMOVED_DEFAULTS])
        for token in ('data-persist=0','qcom-usb-debug=0','sony-touch=1','touch-hid=1','cpufreq=4',
                      'gpu-dcvs=1','sony-buttons-read-qualified=1','sony-buttons-pon-apid=560'):
            self.assertIn(token,new.split())

    def test_wrong_tag_or_changed_defaults_are_not_silently_removed(self):
        old=json.loads((ROOT/'out/d27-pac-abi-release-20261118-067/release.json').read_text())['kernel_args']
        for args in (old.replace('PDX067','PDX066'),old.replace('gpu-fence-wake=1','gpu-fence-wake=0'),
                     old.replace('gpu-pause-us=1000','gpu-pause-us=2000')):
            with self.subTest(args=args),self.assertRaises(ValueError):shorten(args)


if __name__=='__main__':unittest.main()
