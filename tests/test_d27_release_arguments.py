import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pac_release', ROOT / 'scripts/ci/release-d27-pac-abi.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class DiagnosticArguments(unittest.TestCase):
    def test_remove_only_deadline(self):
        before = '-v log=1 log-reserve=1024 autoreset=180'
        self.assertEqual(release.without_autoreset(before), '-v log=1 log-reserve=1024')

    def test_other_reset_policy_retained(self):
        before = 'autoreset=180 log=1 autoreset-clean=1'
        self.assertEqual(release.without_autoreset(before), 'log=1 autoreset-clean=1')

    def test_ambiguous_or_different_baseline_refused(self):
        for before in ('log=1', 'autoreset=0', 'autoreset=120', 'autoreset',
                       'autoreset=180 autoreset=180', 'log=1  autoreset=180'):
            with self.subTest(before=before), self.assertRaises(ValueError):
                release.without_autoreset(before)

    def test_toml_exact_arguments(self):
        text = '[[entry]]\nid = "xnu"\nargs = "log=1 autoreset=180"\n'
        self.assertEqual(release.replace_config_arguments(text, 'log=1 autoreset=180', 'log=1'),
                         '[[entry]]\nid = "xnu"\nargs = "log=1"\n')

    def test_wrong_config_or_duplicate_xnu_refused(self):
        text = '[[entry]]\nid = "xnu"\nargs = "log=1 autoreset=180"\n'
        for config, before in ((text, 'log=1'), (text + text, 'log=1 autoreset=180')):
            with self.subTest(config=config), self.assertRaises(ValueError):
                release.replace_config_arguments(config, before, 'log=1')


if __name__ == '__main__':
    unittest.main()
