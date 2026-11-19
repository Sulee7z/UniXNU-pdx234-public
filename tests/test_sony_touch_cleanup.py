"""Static safety boundaries for removal of the completed touch test probes."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TouchCleanupTests(unittest.TestCase):
    def test_driver_has_no_temporary_workers_or_painters(self):
        text = (ROOT / 'drivers/SonyLxsTouch/SonyTouch.cpp').read_text()
        for marker in ('diagnosticThread', 'logInputTree', 'statusRows',
                       'native_adreno_fences_detail', 'native_sony_cpu_snapshot',
                       'native_touch_rows', '[sony-touch-registry]', '[pdx062-gpu]'):
            self.assertNotIn(marker, text)

    def test_functional_guards_and_error_evidence_remain(self):
        text = (ROOT / 'drivers/SonyLxsTouch/SonyTouch.cpp').read_text()
        for marker in ('void usageGuard(', 'ms<180000;ms+=2', 'publishUsage(device)',
                       'sony_touch_irq_prepare', 'native_sony_touch_pinned_dma',
                       'sw82907_version_supported', 'sw82907_code_crc_result',
                       'publish(Sw82907FrameData{})', 'native_touch_published()',
                       '[sony-touch-xfer]', '[sony-touch-smmu]', '[sony-touch] stage='):
            self.assertIn(marker, text)

    def test_hid_retries_and_blocks_auth_flags_remain(self):
        text = (ROOT / 'scripts/ci/build-sony-touch.py').read_text()
        for marker in ('reportRetry=true', 'setTimeoutMS(8)', 'setTimeoutMS(100)',
                       'builder.audit_hid', 'builder.qualify_edge', 'block_flags'):
            self.assertIn(marker, text)
        self.assertNotIn("commands['CpuRuntimeProbe']", text)


if __name__ == '__main__':
    unittest.main()
