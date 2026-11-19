"""Regression against the actual pre-fix and corrected FD containers."""
import importlib.util
from pathlib import Path
import unittest

DEVICE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('services', DEVICE / 'scripts/check-firmware-services.py')
services = importlib.util.module_from_spec(spec)
spec.loader.exec_module(services)


class FirmwareServices(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = (DEVICE / 'out/firmware-004/SILICIUM_UEFI.fd').read_bytes()
        cls.new = (DEVICE / 'out/firmware-005/SILICIUM_UEFI.fd').read_bytes()
        cls.complete = (DEVICE / 'out/firmware-008/SILICIUM_UEFI.fd').read_bytes()

    def test_old_fd_reproduces_missing_capsule(self):
        report = services.inspect_firmware(self.old)
        self.assertEqual(report['missing_arch_providers'], ['Capsule'])
        self.assertFalse(report['passed'])

    def test_capsule_fix_still_lacked_bds_form_browser(self):
        report = services.inspect_firmware(self.new)
        self.assertEqual(report['missing_arch_providers'], [])
        self.assertEqual(report['missing_menu_modules'], ['SetupBrowser'])
        self.assertTrue(report['capsule_variable_write_depex'])
        self.assertFalse(report['passed'])

    def test_latest_fd_contains_arch_and_bds_services(self):
        report = services.inspect_firmware(self.complete)
        self.assertEqual(report['missing_arch_providers'], [])
        self.assertEqual(report['missing_menu_modules'], [])
        self.assertTrue(report['passed'])
        self.assertFalse(report['hardware_execution_verified'])

    def test_truncated_fd_rejected(self):
        with self.assertRaisesRegex(ValueError, '3 MiB'):
            services.inspect_firmware(self.new[:-1])

    def test_damaged_fv_header_rejected(self):
        data = bytearray(self.new)
        data[44] ^= 1
        with self.assertRaisesRegex(ValueError, 'checksum'):
            services.inspect_firmware(bytes(data))


if __name__ == '__main__':
    unittest.main(verbosity=2)
