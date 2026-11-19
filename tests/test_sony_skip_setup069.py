from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci'))
from platform069.skip_setup import official_values,encode_preferences,menu_entry,merge_existing
OFFICIAL=Path('/mnt/f/UniXNU-Port-artifacts/platform069-20261118/UniXNU/scripts/seed-data-skip-setup.py')


class OfficialSkipSetup(unittest.TestCase):
    def test_target_build_and_exact_official_preferences(self):
        values=official_values(OFFICIAL)
        self.assertEqual(values['com.apple.migration']['LastSystemVersion'],'24A446')
        self.assertTrue(values['com.apple.purplebuddy']['SetupDone'])
        self.assertFalse(values['com.apple.purplebuddy']['daemonizeNeedsToRun'])
        self.assertEqual(len(values['com.apple.purplebuddy.notbackedup']),7)
        self.assertNotIn('SBDisableIdleSleep',values['com.apple.springboard'])
        self.assertFalse(values['com.apple.managedconfiguration.notbackedup']['LockdownActivationIndicatesCloudConfigurationAvailable'])

    def test_no_auto_dim_is_explicit_separate_option(self):
        values=official_values(OFFICIAL,no_auto_dim=True)
        self.assertTrue(values['com.apple.springboard']['SBDisableIdleSleep'])
        self.assertTrue(values['com.apple.springboard']['SBDisableAutoDim'])

    def test_merged_values_preserve_unrelated_existing_preferences(self):
        old={'Other':{'key':7},'SetupDone':False};new=merge_existing(old,{'SetupDone':True})
        self.assertEqual(new['Other'],{'key':7});self.assertFalse(old['SetupDone']);self.assertTrue(new['SetupDone'])
        with self.assertRaises(ValueError):merge_existing([],{'x':1})

    def test_optional_menu_entry_does_not_replace_default_or_normal_seed(self):
        normal=dict(id='xnu',title='Boot iOS',type='xnu',path='Payloads/kernel.macho',initrd='Payloads/scratch-data.img',args='test=1')
        skip=menu_entry(normal,'Payloads/scratch-data-skip-setup.img')
        self.assertEqual(normal['id'],'xnu');self.assertEqual(normal['initrd'],'Payloads/scratch-data.img')
        self.assertEqual(skip['id'],'xnu-skip-setup');self.assertEqual(skip['path'],normal['path'])
        self.assertEqual(skip['args'],normal['args'])


if __name__=='__main__':unittest.main()
