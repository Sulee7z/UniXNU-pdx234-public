#!/usr/bin/env python3
"""Actual068 evidence parser and gate-only source overlay regressions."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ci/platform069/crashes'))
from audit import decode_wait_status, timestamp, analyze, FRESH
from source import preserve_crash_messages, launch_policy
from runtime import merge_icon_environment


class EvidenceTests(unittest.TestCase):
    def test_wait_status_is_not_signal(self):
        self.assertEqual(decode_wait_status(0x100)['exit_code'], 1)
        self.assertEqual(decode_wait_status(0x300)['exit_code'], 3)
        self.assertEqual(decode_wait_status(0xfffffd00)['exit_code'], 253)

    def test_signal_and_core_flag(self):
        self.assertEqual(decode_wait_status(5)['signal'], 5)
        self.assertEqual(decode_wait_status(10)['signal'], 10)
        self.assertTrue(decode_wait_status(0x86)['core_flag'])

    def test_unnormalized_kernel_microseconds(self):
        self.assertEqual(timestamp('[  689.1007289]: x'), 690.007289)
        self.assertEqual(timestamp('[  582.274855]: x'), 582.274855)
        self.assertIsNone(timestamp('cached PID1 [panic] text'))

    def test_actual068_unique_pid_counts_and_shutdown(self):
        d = analyze(FRESH / 'device-post068-readonly-001/decoded/PDX068-3fbe8890')
        self.assertEqual(d['unique_exit_pids'], 47)
        for name in ('bluetoothd', 'fskitd', 'pfd'):
            self.assertEqual(d['exit_by_name'][name]['pid_count'], 13)
            self.assertEqual(d['exit_by_name'][name]['classification'], ['ordinary-exit'])
        self.assertEqual(len(d['shutdown_requests']), 1)
        self.assertEqual(d['shutdown_requests'][0]['name'], 'SpringBoard')
        self.assertEqual(d['shutdown_requests'][0]['pid'], 539)
        self.assertEqual(d['shutdown_timestamp_s'], 715.551811)
        hid = next(e for e in d['exit_events'] if e['pid'] == 102)
        self.assertEqual(hid['signal'], 10)
        self.assertTrue(hid['after_shutdown_request'])

    def test_budget_vs_idle_and_corpse_count(self):
        d = analyze(FRESH / 'device-post068-readonly-001/decoded/PDX068-3fbe8890')
        budgets = [r for r in d['kill_events'] if r['method'] != 'killing_idle_process']
        self.assertEqual(len(budgets), 5)
        self.assertEqual(len(d['kill_events']), 24)
        self.assertEqual({r['name'] for r in budgets}, {'Spotlight', 'WidgetRenderer_Default', 'iconservicesagent', 'com.apple.MapKit.SnapshotService'})
        # Two notification lines without PID do not become two Settings crashes.
        self.assertEqual(len([r for r in d['corpse_notifications'] if r['name'] == 'Preferences']), 2)
        self.assertNotIn('Preferences', d['exit_by_name'])


class OverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.boot = (ROOT / 'ci/platform067/arm64e/logging067/build-002/BootLog.c').read_text()

    def test_gate_reuses_official_selector_without_enabling_diag(self):
        new = preserve_crash_messages(self.boot)
        self.assertIn('if (diag == 1 || log_crash_evidence_on) text = diag_msg_lines', new)
        self.assertEqual(new.count('diag == 1 && &boot_diag_shot_tick'), self.boot.count('diag == 1 && &boot_diag_shot_tick'))
        self.assertEqual(new.count('kernel_thread_start_priority(diag_thread'), self.boot.count('kernel_thread_start_priority(diag_thread'))
        self.assertNotIn('diag = 1; log_crash', new)

    def test_gate_is_single_use(self):
        with self.assertRaises(ValueError):
            preserve_crash_messages(preserve_crash_messages(self.boot))

    def test_current_official_policy_keeps_sony_builtin_string(self):
        old = 'char PE_builtin_boot_args[]="old=1"\nint old_policy;\n'
        fresh = 'char PE_builtin_boot_args[]="uefi-watchdog=1"\nint enable_jobs;\n'
        new = launch_policy(old, fresh)
        self.assertEqual(new, 'char PE_builtin_boot_args[]="old=1"\nint enable_jobs;\n')

    def test_policy_rejects_ambiguous_builtin(self):
        with self.assertRaises(ValueError):
            launch_policy('', 'char PE_builtin_boot_args[]="x=1"')

    def test_icon_environment_composes_without_job_or_budget_changes(self):
        old = {'org.unixnu.wifi': {'EXISTING': '1'}}
        new = merge_icon_environment(old)
        self.assertEqual(old, {'org.unixnu.wifi': {'EXISTING': '1'}})
        self.assertEqual(new['org.unixnu.wifi'], old['org.unixnu.wifi'])
        self.assertEqual(new['com.apple.iconservices.iconservicesagent'],
                         {'FORCE_SOFTWARE_RENDERER': '0', 'CI_ENABLE_METAL_GPU': '0'})
        self.assertEqual(merge_icon_environment(new), new)

    def test_icon_environment_conflict_is_not_silently_overridden(self):
        with self.assertRaises(ValueError):
            merge_icon_environment({'com.apple.iconservices.iconservicesagent': {'FORCE_SOFTWARE_RENDERER': '1'}})


if __name__ == '__main__':
    unittest.main()
