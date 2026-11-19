import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('platform_package', ROOT / 'scripts/ci/package-sony-platform067.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PlatformArguments(unittest.TestCase):
    def setUp(self):
        self.before = 'data-persist=0 build-tag=PDX066 cpufreq=1 vsync=60 first-frame-diag=1 sony-touch=1 touch-hid=1'

    def test_only_reviewed_tokens_change(self):
        self.assertEqual(package.updated_arguments(self.before, {'cpufreq': 4, 'vsync': 120}),
            self.before.replace('PDX066', 'PDX067').replace('cpufreq=1', 'cpufreq=4').replace('vsync=60', 'vsync=120'))

    def test_added_button_token_is_unique(self):
        value = package.updated_arguments(self.before, {'sony-buttons': 1})
        self.assertEqual(value.split().count('sony-buttons=1'), 1)

    def test_source_qualified_pon_read_parameters(self):
        value = package.updated_arguments(self.before, {'sony-buttons': 1,
            'sony-buttons-read-qualified': 1, 'sony-buttons-pon-apid': 560, 'storage-probe': 1})
        self.assertIn('sony-buttons-pon-apid=560', value.split())
        self.assertNotIn('sony-buttons-gpio-apid', value)
        self.assertIn('data-persist=0', value.split())

    def test_security_persistence_and_unknown_tokens_refused(self):
        for changes in ({'data-persist': 2}, {'qcom-usb-debug': 1}, {'build-tag': 67},
                        {'smp': 0}, {'sony-touch': 0}, {'no-pac': 1}, {'vsync': '120'}, {'cpufreq': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                package.updated_arguments(self.before, changes)

    def test_ambiguous_baseline_refused(self):
        for before in (self.before + ' vsync=60', self.before + ' vsync=120', self.before.replace('PDX066', 'PDX065')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                package.updated_arguments(before, {'vsync': 120})

    def test_overlong_final_request_is_rejected_before_packaging(self):
        import json
        old=json.loads((ROOT/'out/d27-pac-abi-release-20261118-066/release.json').read_text())['kernel_args']
        changes={
            'cpufreq':4,'gpu-dcvs':1,'gpu-dcvs-min':4,'gpu-fence-wake':1,'gpu-pause-us':1000,
            'sony-display-timing':1,'sony-perf-samples':60,'vsync':120,'first-frame-diag':0,
            'gpu-trace':0,'sheng-gpu-trace':0,'sony-buttons':1,'sony-buttons-read-qualified':1,
            'sony-buttons-pon-apid':560,'wifi':0,'bluetooth':0,'backlight':1,'storage-probe':1}
        with self.assertRaisesRegex(ValueError,'1041 argument bytes'):
            package.updated_arguments(old,changes)


if __name__ == '__main__':
    unittest.main()
