import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('usb_capture', ROOT / 'scripts/capture-pdx234-usb.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def port(device, vid=0x1209, pid=0x316d, serial='PDX234XnuLog'):
    return SimpleNamespace(device=device, vid=vid, pid=pid, serial_number=serial)


class PortIdentity(unittest.TestCase):
    def test_unrelated_ports_are_not_opened(self):
        self.assertIsNone(capture.select_port([port('COM1', None, None, None),
                                             port('COM2', serial='OtherDevice')], None))

    def test_exact_identity(self):
        target = port('COM7')
        self.assertIs(capture.select_port([port('COM1', None, None, None), target], None), target)

    def test_duplicate_identity_refused(self):
        with self.assertRaises(ValueError):
            capture.select_port([port('COM7'), port('COM8')], None)

    def test_explicit_port_case_insensitive(self):
        target = port('COM7', serial=None)
        self.assertIs(capture.select_port([target, port('COM8')], 'com7'), target)


if __name__ == '__main__':
    unittest.main()
