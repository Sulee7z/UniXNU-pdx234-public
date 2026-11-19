"""Source guard and refresh-claim regressions. Run with unittest discovery."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'ci/platform067/performance'))
from rates import interface_rate,present_rate
from source import parse_opps,replace_once,gpu_source,CPU_SHA,cpu_source


class SourceGuards(unittest.TestCase):
    def test_unique_source_anchor(self):
        self.assertEqual(replace_once('a CPU b','CPU','GPU'),'a GPU b')
        for text in ('CPU CPU','missing'):
            with self.assertRaises(ValueError):replace_once(text,'CPU','GPU')

    def test_refuse_unpinned_source(self):
        with self.assertRaises(ValueError):cpu_source('unreviewed')
        with self.assertRaises(ValueError):gpu_source('unreviewed',[])

    def test_exact_vote_table_parser(self):
        text='static const ShengGmuOpp sheng_gpu_opps[]={\n{0,0,0,0,0},\n{124800000,52,2136718,0,0},\n};'
        self.assertEqual(parse_opps(text),[(0,0,0,0,0),(124800000,52,2136718,0,0)])

    def test_pac_recipe_does_not_duplicate_frontend_flags(self):
        spec=importlib.util.spec_from_file_location('performance_builder',ROOT/'scripts/ci/build-sony-platform-performance.py')
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        dep={'source':'old.cpp','command':['clang','-c','old.cpp','-o','old.o','-MD','-MF','old.d','-MT','old',
                                         '-fptrauth-function-pointer-type-discrimination']}
        command=mod.compile_command(dep,Path('new.cpp'),Path('new.o'))
        self.assertNotIn('-MF',command)
        self.assertEqual(command[command.index('-o')+1],'new.o')
        self.assertEqual(command.count('-fptrauth-block-descriptor-pointers'),1)
        dep['command']=command;dep['source']='new.cpp'
        self.assertEqual(mod.compile_command(dep,Path('next.cpp'),Path('next.o')).count('-fptrauth-block-descriptor-pointers'),1)


class RefreshClaims(unittest.TestCase):
    @staticmethod
    def sample(delta,interval=10000000,timing=1,count=1):
        return interface_rate(f'interface=1 delta={delta} elapsed-us={interval} timing={timing:x} counter-enable={count:x}')

    def test_requested_120_does_not_change_60_measurement(self):
        row=self.sample(600)
        self.assertEqual(row['observed_interface_hz'],60)
        self.assertFalse(row['panel_refresh_verified'])

    def test_even_120_dpu_is_not_panel_self_refresh_proof(self):
        row=self.sample(1200)
        self.assertEqual(row['observed_interface_hz'],120)
        self.assertIsNone(row['panel_refresh_hz'])

    def test_nonmoving_disabled_reset_short_samples(self):
        for row in (self.sample(0),self.sample(600,timing=0),self.sample(600,count=0),
                    self.sample(0xffffffff),self.sample(1,1000),self.sample(600,0)):
            self.assertFalse(row['counter_valid'])
            self.assertIsNone(row['observed_interface_hz'])

    def test_copy_and_retire_are_not_compositor_fps(self):
        row=present_rate('elapsed-us=10000000 copy-delta=720 retire-delta=710 requested-vsync=120')
        self.assertEqual(row['copies_per_second'],72)
        self.assertEqual(row['retirements_per_second'],71)
        self.assertEqual(row['requested_vsync_hz'],120)
        self.assertIsNone(row['compositor_fps'])

    def test_refuse_nonpositive_present_interval(self):
        with self.assertRaises(ValueError):present_rate('elapsed-us=0 copy-delta=1 retire-delta=1 requested-vsync=120')


if __name__=='__main__':unittest.main()
