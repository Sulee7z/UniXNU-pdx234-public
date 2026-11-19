import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('d27_bulk_rebase', ROOT / 'scripts/ci/rebase-d27-sheng27-overlays.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class BulkOverlayTests(unittest.TestCase):
    def test_rebase_preserves_every_d27_added_line(self):
        old = (ROOT / 'patches/xnu/ios27-d27-sanitizer-state.patch').read_text()
        new = MOD.rebase_sanitizer(old)
        changed = lambda text: [line for line in text.splitlines() if line.startswith('+')]
        self.assertEqual(changed(old), changed(new))
        self.assertEqual(new.count(' #include <sys/trust_caches.h>'), 1)
        self.assertIn('task_set_sanitizer_config(new_task, sanitizer_config)', new)
        self.assertIn('return ENOTSUP;', new)
        self.assertIn('"D27 copyin prefix"', new)
        self.assertIn('-\t\t\tif (px_args.attr_size == PSA_DARWIN26_SIZE)', new)

    def test_unknown_context_fails_instead_of_dropping_hunk(self):
        with self.assertRaises(ValueError):
            MOD.rebase_sanitizer('not the audited patch')

    def test_already_rebased_patch_is_not_applied_twice(self):
        raw = (ROOT / 'patches/xnu/ios27-d27-sanitizer-state.patch').read_text()
        with self.assertRaises(ValueError):
            MOD.rebase_sanitizer(MOD.rebase_sanitizer(raw))


if __name__ == '__main__':
    unittest.main()
