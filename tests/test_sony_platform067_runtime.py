from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci'))
from platform067.runtime import refresh_sample,summarize


class RuntimeEvidence(unittest.TestCase):
    def test_idle_and_soft_limit_are_not_fatal(self):
        data=summarize('memorystatus: app exceeded mem limit: ActiveSoft 200 MB (non-fatal)\n'
            'memorystatus: killing_idle_process pid 4 (long-idle-exit 0 200s)\n'
            'memorystatus: app exceeded mem limit: InactiveHard 14 MB (fatal)\n')
        counts=data['line_counts']
        self.assertEqual(counts['nonfatal_process_limit_lines'],1)
        self.assertEqual(counts['fatal_process_limit_lines'],1)
        self.assertEqual(counts['long_idle_exit_lines'],1)
        self.assertFalse(data['all_app_exit_causes_proven'])

    def test_request_does_not_turn_into_panel_or_compositor_fps(self):
        sample=refresh_sample('[sony-present-rate] elapsed-us=10000000 copy-delta=20 retire-delta=20 requested-vsync=120 panel-hz=unmeasured')
        self.assertEqual(sample['retirements_per_second'],2)
        self.assertEqual(sample['requested_vsync_hz'],120)
        self.assertIsNone(sample['compositor_fps'])
        self.assertIsNone(sample['panel_refresh_hz'])

    def test_interface120_still_has_no_panel_proof(self):
        sample=refresh_sample('[sony-dpu-rate] interface=1 timing=1 counter-enable=1 delta=1200 elapsed-us=10000000')
        self.assertEqual(sample['observed_interface_hz'],120)
        self.assertFalse(sample['panel_refresh_verified'])

    def test_wrap_reset_and_disabled_counter_rejected(self):
        for extra in ('timing=0 counter-enable=1 delta=600', 'timing=1 counter-enable=0 delta=600',
                      'timing=1 counter-enable=1 delta=4294967000'):
            sample=refresh_sample('[sony-dpu-rate] interface=1 elapsed-us=10000000 '+extra)
            self.assertFalse(sample['counter_valid'])

    def test_malformed_rate_does_not_discard_other_evidence(self):
        result=summarize('[sony-present-rate] elapsed-us=0\ndisk2s1 cannot enter tx; 28\n')
        self.assertEqual(len(result['malformed_rate_lines']),1)
        self.assertEqual(result['line_counts']['apfs_enospc_lines'],1)

    def test_actual_touch_sample_is_parsed_without_ui_claim(self):
        result=summarize('[sony-touch] s=4 e=0 fw=00000303 loaded=0 clk=0 frames=4570 valid=4526 bad=0 contacts=0 hid=4526 result=0')
        self.assertEqual(result['touch_last_sample']['hid_reports'],4526)
        self.assertFalse(result['panel_refresh_verified'])
        self.assertFalse(result['pac_cause_for_all_app_exits_proven'])

    def test_official_exit_reason_keeps_raw_status_without_inferred_cause(self):
        result=summarize('unixnu-exit: Example[123] status=0xb reason=2/0x9 csflags=0x120 description=raw reason\n')
        row=result['official_process_exit_records'][0]
        self.assertEqual(row['pid'],123)
        self.assertEqual(row['wait_status'],11)
        self.assertEqual(row['reason_namespace'],2)
        self.assertEqual(row['reason_code'],9)
        self.assertEqual(row['description'],'raw reason')
        self.assertFalse(result['all_app_exit_causes_proven'])


if __name__=='__main__':unittest.main()
