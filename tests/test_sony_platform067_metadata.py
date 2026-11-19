import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('metadata067',ROOT/'scripts/ci/finalize-sony-platform067-metadata.py')
metadata=importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


class MetadataNormalization(unittest.TestCase):
    def test_historical_fields_change_without_image_or_security_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);old=base/'old';new=base/'new';old.mkdir();new.mkdir()
            image=new/'boot.img';raw=b'bounded test image\0';image.write_bytes(raw)
            sha=hashlib.sha256(raw).hexdigest()
            prior=dict(sha256='source-image',kernel_args='build-tag=PDX066 cpufreq=1 data-persist=0')
            receipt=dict(label='PAC-ABI-067',source_image_sha256='source-image',image=str(image),sha256=sha,
                kernel_args='build-tag=PDX067 cpufreq=4 data-persist=0',arguments_added=['build-tag=PDX066'],
                first_frame_diagnostic_arguments=['first-frame-diag=1'],ui_tests_receipt='historical-ui',
                ui_tests_sha256='historical-sha',original_android_sha256='android',adt_sha256='adt',
                metal_runtime=dict(trust_sha256='trust'),block_descriptor_abi=dict(passed=True),
                platform067_feature_status=dict(wifi=dict(implemented=False,hardware_verified=False)))
            (old/'release.json').write_text(json.dumps(prior));original=json.dumps(receipt)
            (new/'release.json').write_text(original)
            with patch.object(sys,'argv',['metadata','--release',str(new),'--baseline',str(old)]):metadata.main()
            after=json.loads((new/'release.json').read_text())
            self.assertEqual(image.read_bytes(),raw)
            self.assertEqual((new/'release.before-metadata-normalization.json').read_text(),original)
            self.assertEqual(after['arguments_removed'],['build-tag=PDX066','cpufreq=1'])
            self.assertEqual(after['arguments_added'],['build-tag=PDX067','cpufreq=4'])
            self.assertNotIn('ui_tests_receipt',after)
            self.assertEqual(after['historical066_ui_tests_receipt'],'historical-ui')
            for key in ('sha256','original_android_sha256','adt_sha256','metal_runtime','block_descriptor_abi','platform067_feature_status'):
                self.assertEqual(after[key],receipt[key])
            with patch.object(sys,'argv',['metadata','--release',str(new),'--baseline',str(old)]):
                with self.assertRaises(ValueError):metadata.main()


if __name__=='__main__':unittest.main()
