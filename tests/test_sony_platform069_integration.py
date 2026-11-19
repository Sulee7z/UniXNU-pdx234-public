import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci'))
from platform069.integration import BASELINE_SHA,expected_adapters,validate


class Native069Guards(unittest.TestCase):
    def setUp(self):
        self.record=dict(baseline_native_sha256=BASELINE_SHA,
            virtual_backends_selected=False,device_operations=False,
            inherited_block_descriptor_objects=66,all_baseline_archive_members_retained=True,
            inputs={'/reviewed/input':'a'*64},compile_receipts=[])

    def test_only_exact_full068_native_is_accepted(self):
        with patch('platform069.integration.sha',return_value='a'*64):validate(self.record)
        for key,value in [('baseline_native_sha256','80b2b18120eafde479aa2eaebd4017a677a67405b0ba0fe33e8d00ad6b6bc3dc'),
                          ('virtual_backends_selected',True),('inherited_block_descriptor_objects',65),
                          ('all_baseline_archive_members_retained',False),('device_operations',True)]:
            changed=copy.deepcopy(self.record);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate(changed)

    def test_changed_input_never_reuses_a_receipt(self):
        with patch('platform069.integration.sha',return_value='b'*64),self.assertRaises(ValueError):validate(self.record)
        self.record['inputs']={}
        with self.assertRaises(ValueError):validate(self.record)

    def test_qualifier_cannot_load_arbitrary_python_modules(self):
        for module in ['os','platform067.arm64e.source','platform069.crashes.__init__..os','platform069']:
            record=copy.deepcopy(self.record);record['source_qualifiers']=[dict(module=module,sha256='a'*64)]
            with self.subTest(module=module),self.assertRaises(ValueError):expected_adapters(record)

    def test_qualifier_requires_real_file_and_matching_reviewed_hash(self):
        record=copy.deepcopy(self.record);path=ROOT/'ci/platform069/skip_setup.py'
        record['source_qualifiers']=[dict(module='platform069.skip_setup',sha256='a'*64)]
        with self.assertRaises(ValueError):expected_adapters(record)
        # Even a named069 module with a matching hash cannot qualify source
        # unless it provides an explicit nonempty callable ADAPTERS table.
        record['inputs'][str(path)]='a'*64
        with patch('platform069.integration.sha',return_value='a'*64),self.assertRaises(ValueError):expected_adapters(record)


if __name__=='__main__':unittest.main()
