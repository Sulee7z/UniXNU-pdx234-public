import importlib.util
from pathlib import Path
import unittest

DEVICE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runner_identities', DEVICE / 'scripts/ci/import-runner-identities.py')
identities = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identities)


class RunnerIdentityTests(unittest.TestCase):
    def test_runner_address_is_not_used(self):
        row = {'name': '_api', 'native': '0xdeadbeef', 'how': 'reference-symbol'}
        self.assertEqual(identities.resolve_reference_function(row, {'_api': {0x1234}}), ('_api', 0x1234))

    def test_uncertain_names_and_ambiguous_local_symbols_are_not_transferred(self):
        for how in ('pure-leaf', 'calls', 'string', 'vtable'):
            self.assertIsNone(identities.resolve_reference_function({'name': '_api', 'how': how}, {'_api': {1}}))
        for name in ('CHECKPOINT', '_api.cold.1', '_OUTLINED_FUNCTION_2', '_api.llvm.1'):
            self.assertIsNone(identities.resolve_reference_function({'name': name, 'how': 'reference-order'}, {name: {1}}))
        self.assertIsNone(identities.resolve_reference_function({'name': '_api', 'how': 'reference-symbol'}, {'_api': {1, 2}}))


if __name__ == '__main__':
    unittest.main()
