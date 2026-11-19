import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('radio_size',ROOT/'scripts/ci/build-sony-radio-core-size.py')
size=importlib.util.module_from_spec(spec)
spec.loader.exec_module(size)


class CoreSizeRecipe(unittest.TestCase):
    def test_remove_only_dependency_side_effect_arguments(self):
        command=['clang','-c','-O2','-MD','-MF','old.d','-MT','old','-I','headers',
                 '-Xclang','-fptrauth-block-descriptor-pointers','-fptrauth-function-pointer-type-discrimination',
                 'source.c','-o','old.o']
        result=size.clean(command)
        self.assertEqual(result,['clang','-c','-O2','-I','headers','-Xclang',
            '-fptrauth-block-descriptor-pointers','-fptrauth-function-pointer-type-discrimination','source.c','-o','old.o'])

    def test_namespace_postprocessing_is_required_not_removed_for_size(self):
        text=(ROOT/'scripts/ci/build-sony-radio-core-size.py').read_text()
        self.assertIn("sha(mapping)!=dep['namespace_map_sha256']",text)
        self.assertIn("'--redefine-syms='+str(mapping)",text)
        self.assertIn("object_count=125",text)
        self.assertIn("source_text_changed=False",text)
        self.assertIn("firmware_or_driver_removed=False",text)


if __name__=='__main__':unittest.main()
